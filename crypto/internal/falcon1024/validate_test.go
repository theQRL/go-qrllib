package falcon1024

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/internal/testutil"
)

// --- key constructions ------------------------------------------------------

// constantPolynomial returns the public polynomial h(x) = k.
func constantPolynomial(k int32) ringElement {
	var h ringElement
	h[0] = fieldFromSmall(k)
	return h
}

// monomialPolynomial returns the public polynomial h(x) = k*x^j.
func monomialPolynomial(k int32, j int) ringElement {
	var h ringElement
	h[j] = fieldFromSmall(k)
	return h
}

// ratioPolynomial returns a/b mod q (b must be invertible), the shape of a
// public key whose owner, or anyone who guesses b, holds a short basis.
func ratioPolynomial(t *testing.T, a, b smallPolynomial) ringElement {
	t.Helper()
	h, ok := computePublic(b, a)
	if !ok {
		t.Fatal("divisor is not invertible mod q")
	}
	return h
}

// constantSmallPolynomial returns the small polynomial c, for use as a
// numerator or an integer divisor.
func constantSmallPolynomial(c int32) smallPolynomial {
	var p smallPolynomial
	p[0] = c
	return p
}

// seededSmallPolynomial draws coefficients uniformly from [-bound, bound].
func seededSmallPolynomial(label string, bound int32) smallPolynomial {
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte(label))
	var p smallPolynomial
	var buf [4]byte
	for i := range p {
		_, _ = rng.Read(buf[:])
		v := int32(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16)
		p[i] = v%(2*bound+1) - bound
	}
	return p
}

// encodePublic serialises h in the NIST public-key format.
func encodePublic(t *testing.T, h ringElement) []byte {
	t.Helper()
	var pk [PublicKeySize]byte
	if err := pkEncode(pk[:], h); err != nil {
		t.Fatal(err)
	}
	return pk[:]
}

// polynomialWithSquaredNorm returns a polynomial with pseudo-random signs and
// magnitudes whose centred squared norm is exactly target, by choosing its
// last two coefficients. Its small multiples are as long as an honest key's.
func polynomialWithSquaredNorm(t *testing.T, label string, target uint64) ringElement {
	t.Helper()
	for attempt := range 1000 {
		p := seededSmallPolynomial(fmt.Sprintf("%s %d", label, attempt), 1740) // 1022 * 1740^2 / 3 sits a little under 2^30
		var sum uint64
		for i := 0; i < n-2; i++ {
			sum += uint64(int64(p[i]) * int64(p[i]))
		}
		for u := int64(0); u <= 6144 && sum+uint64(u*u) <= target; u++ {
			rem := int64(target - sum - uint64(u*u))
			w := int64(math.Sqrt(float64(rem)))
			for w*w > rem {
				w--
			}
			for (w+1)*(w+1) <= rem {
				w++
			}
			if w <= 6144 && w*w == rem {
				p[n-2], p[n-1] = int32(u), int32(w)
				h := mustSmall(t, p)
				if centredSquaredNorm(h) != target {
					t.Fatal("construction did not hit the target norm")
				}
				return h
			}
		}
	}
	t.Fatalf("no polynomial with squared norm %d found", target)
	return ringElement{}
}

// centredSquaredNorm is ||h||^2 with every coefficient taken in (-q/2, q/2].
func centredSquaredNorm(h ringElement) uint64 {
	var norm uint64
	for _, c := range h {
		v := int64(c)
		if v > q/2 {
			v -= q
		}
		norm += uint64(v * v)
	}
	return norm
}

// oversizedStrongPrivateKey builds, bypassing the import checks, a key whose
// (f, g) violate the key-generation squared-norm bound while its public half
// is an ordinary uniform polynomial.
func oversizedStrongPrivateKey(t *testing.T) *PrivateKey {
	t.Helper()
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("oversized private key"))
	for range 400 {
		f := sampleGaussianPolynomial(rng)
		g := sampleGaussianPolynomial(rng)
		if coefficientsExceedBound(f, fgBound) || coefficientsExceedBound(g, fgBound) {
			continue
		}
		if !squaredNormExceedsBound(f, g, keygenSqNormBound) {
			continue
		}
		h, ok := computePublic(f, g)
		if !ok {
			continue
		}
		if c, _ := weakPublicKeyMultiplier(h); c != 0 {
			continue
		}
		ntruF, ntruG, ok := solveNTRU(f, g)
		if !ok {
			continue
		}
		priv, err := initPrivateKey(&PrivateKey{}, f, g, ntruF, ntruG, h)
		if err != nil {
			t.Fatal(err)
		}
		return priv
	}
	t.Fatal("no oversized (f, g) with a solvable NTRU equation found")
	return nil
}

// --- forgery against a constant or monomial key ---------------------------

// gaussReduce reduces the basis {(q, 0), (-k, 1)} of {(x, y): x + k*y = 0 mod q}.
func gaussReduce(k int64) (u, v [2]float64) {
	u = [2]float64{float64(q), 0}
	v = [2]float64{float64(-k), 1}
	for {
		if u[0]*u[0]+u[1]*u[1] > v[0]*v[0]+v[1]*v[1] {
			u, v = v, u
		}
		m := math.Round((u[0]*v[0] + u[1]*v[1]) / (u[0]*u[0] + u[1]*u[1]))
		w := [2]float64{v[0] - m*u[0], v[1] - m*u[1]}
		if m == 0 || w[0]*w[0]+w[1]*w[1] >= v[0]*v[0]+v[1]*v[1] {
			return u, v
		}
		v = w
	}
}

// babaiResidual returns the residual of target t after nearest-plane
// rounding against the reduced basis (b1, b2).
func babaiResidual(b1, b2, t [2]float64) (x, y int64) {
	mu := (b2[0]*b1[0] + b2[1]*b1[1]) / (b1[0]*b1[0] + b1[1]*b1[1])
	b2s := [2]float64{b2[0] - mu*b1[0], b2[1] - mu*b1[1]}
	beta := math.Round((t[0]*b2s[0] + t[1]*b2s[1]) / (b2s[0]*b2s[0] + b2s[1]*b2s[1]))
	r := [2]float64{t[0] - beta*b2[0], t[1] - beta*b2[1]}
	alpha := math.Round((r[0]*b1[0] + r[1]*b1[1]) / (b1[0]*b1[0] + b1[1]*b1[1]))
	return int64(math.Round(r[0] - alpha*b1[0])), int64(math.Round(r[1] - alpha*b1[1]))
}

// forgeUnderMonomial produces a detached signature of message under the
// public key k*x^j without any secret, by rounding each hash coefficient
// against the reduced two-dimensional lattice of k. It reports whether the
// primitive verifier (bypassing key validation) accepts it.
func forgeUnderMonomial(t *testing.T, k int32, j int, message []byte) bool {
	t.Helper()
	pub, err := newPublicKeyFromH(monomialPolynomial(k, j))
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceSize]byte
	hash := sha3.NewSHAKE256()
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write(message)
	c0 := hashToPoint(hash)

	b1, b2 := gaussReduce(int64(k))
	var s2 smallPolynomial
	for m, c := range c0 {
		v := int64(c)
		if v > q/2 {
			v -= q
		}
		_, y := babaiResidual(b1, b2, [2]float64{float64(v), 0})
		if y > maxCompressedCoefficient || y < -maxCompressedCoefficient {
			return false
		}
		// (x^j * s2)_m = s2_{m-j} for m >= j and -s2_{m-j+n} otherwise.
		if m >= j {
			s2[m-j] = int32(y)
		} else {
			s2[m-j+n] = -int32(y)
		}
	}
	sig, err := detachedSignatureEncode(nonce, s2)
	if err != nil {
		return false
	}
	return Verify(&pub, message, sig) == nil
}

// --- the rule ----------------------------------------------------------------

// TestWeakKeyRuleAcceptsGeneratedKeys checks that keys from the key
// generator pass the rule, through ValidatePublicKey and directly.
func TestWeakKeyRuleAcceptsGeneratedKeys(t *testing.T) {
	for i := range 8 {
		seed := make([]byte, SeedSize)
		seed[0] = byte(i)
		priv, err := NewPrivateKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		pk := priv.PublicKey().Bytes()
		if validateErr := ValidatePublicKey(pk); validateErr != nil {
			t.Fatalf("seed %d: generated key rejected: %v", i, validateErr)
		}
		h, err := pkDecode(pk)
		if err != nil {
			t.Fatal(err)
		}
		if c, _ := weakPublicKeyMultiplier(h); c != 0 {
			t.Fatalf("seed %d: generated key flagged weak with multiplier %d", i, c)
		}
	}
}

// Every constant or monomial key fails the rule at c = 1: its centred
// coefficient has magnitude at most q/2, so ||h||^2 < 2^30. The forgery
// column records which of them the two-dimensional rounding forgery defeats
// outright; the others hand the forger an even shorter lattice vector.
func TestWeakKeyRuleRejectsConstantsAndMonomials(t *testing.T) {
	message := []byte("constant and monomial keys")
	for _, tc := range []struct {
		k         int32
		j         int
		forgeable bool
	}{
		{1, 0, false}, {13, 0, false}, {20, 0, true}, {111, 0, true}, {800, 0, true},
		{2000, 0, true}, {6145, 0, false}, {12000, 0, true}, {12288, 0, false},
		{111, 777, true}, {2000, 5, true},
	} {
		h := monomialPolynomial(tc.k, tc.j)
		centred := int64(tc.k)
		if centred > q/2 {
			centred -= q
		}
		if c, norm := weakPublicKeyMultiplier(h); c != 1 || norm != uint64(centred*centred) {
			t.Errorf("k=%d x^%d: multiplier, norm = %d, %d; want 1, %d", tc.k, tc.j, c, norm, centred*centred)
		}
		if _, err := NewPublicKey(encodePublic(t, h)); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Errorf("k=%d x^%d: NewPublicKey error = %v, want ErrWeakPublicKey", tc.k, tc.j, err)
		}
		if got := forgeUnderMonomial(t, tc.k, tc.j, message); got != tc.forgeable {
			t.Errorf("k=%d x^%d: forgery verifies = %v, want %v", tc.k, tc.j, got, tc.forgeable)
		}
	}
	if c, norm := weakPublicKeyMultiplier(ringElement{}); c != 1 || norm != 0 {
		t.Errorf("zero key: multiplier, norm = %d, %d; want 1, 0", c, norm)
	}
}

// TestWeakKeyRuleRejectsSmallIntegerRatios checks the multiplier scan on
// keys a/c up to the last multiplier scanned, and that the next one is left
// alone.
func TestWeakKeyRuleRejectsSmallIntegerRatios(t *testing.T) {
	a := seededSmallPolynomial("ratio numerator", 600)
	for _, c := range []int32{1, 2, 907, 1024} {
		h := ratioPolynomial(t, a, constantSmallPolynomial(c))
		got, _ := weakPublicKeyMultiplier(h)
		if got == 0 || got > int(c) {
			t.Errorf("a/%d: multiplier = %d, want one in [1, %d]", c, got, c)
		}
	}
	// One past the scan: outside the forgeable window (N > 1025^2), so the
	// rule leaves it alone, and documents where its coverage stops.
	h := ratioPolynomial(t, a, constantSmallPolynomial(weakKeyMultiplierBound+1))
	if c, _ := weakPublicKeyMultiplier(h); c != 0 {
		t.Errorf("a/%d: multiplier = %d, want 0", weakKeyMultiplierBound+1, c)
	}
}

// TestWeakKeyRuleBoundary pins the norm bound to the exact value: 2^30 - 1
// is weak and 2^30 is strong for c = 1.
func TestWeakKeyRuleBoundary(t *testing.T) {
	// For c = 1 the rule reads ||h||^2 + 1 <= 2^30.
	weak := polynomialWithSquaredNorm(t, "boundary weak", weakKeySquaredNormBound-1)
	if c, norm := weakPublicKeyMultiplier(weak); c != 1 || norm != weakKeySquaredNormBound-1 {
		t.Errorf("||h||^2 = 2^30-1: multiplier, norm = %d, %d; want 1, 2^30-1", c, norm)
	}
	strong := polynomialWithSquaredNorm(t, "boundary strong", weakKeySquaredNormBound)
	if c, _ := weakPublicKeyMultiplier(strong); c != 0 {
		t.Errorf("||h||^2 = 2^30: multiplier = %d, want 0", c)
	}
	if err := ValidatePublicKey(encodePublic(t, strong)); err != nil {
		t.Errorf("||h||^2 = 2^30 rejected: %v", err)
	}
}

// A key a/b for a sparse non-integer b also hands a short basis to anyone who
// guesses b; the rule does not look for such b. Recorded so the limit is a
// known one.
func TestWeakKeyRuleKnownGapSparseDivisor(t *testing.T) {
	a := seededSmallPolynomial("sparse divisor numerator", 3)
	var b smallPolynomial
	b[0], b[3], b[7] = 1, -1, 1
	h := ratioPolynomial(t, a, b)
	if c, _ := weakPublicKeyMultiplier(h); c != 0 {
		t.Fatalf("a/(1 - x^3 + x^7) flagged by multiplier %d; the known gap closed, update the documentation", c)
	}
}

// TestValidatePublicKeyErrors checks the sentinel contract: malformed
// encodings wrap ErrInvalidPublicKey, weak keys wrap ErrWeakPublicKey only.
func TestValidatePublicKeyErrors(t *testing.T) {
	priv := testPrivateKey(t)
	pk := priv.PublicKey().Bytes()
	if err := ValidatePublicKey(pk); err != nil {
		t.Errorf("generated key: %v", err)
	}
	for name, bad := range map[string][]byte{"nil": nil, "short": pk[:PublicKeySize-1], "header": append([]byte{0xFF}, pk[1:]...)} {
		if err := ValidatePublicKey(bad); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
			t.Errorf("%s: error = %v, want ErrInvalidPublicKey", name, err)
		}
	}
	err := ValidatePublicKey(encodePublic(t, constantPolynomial(111)))
	if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) || errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
		t.Errorf("constant key: error = %v, want ErrWeakPublicKey only", err)
	}
}

// TestNewPrivateKeyAppliesWeakKeyRuleThenBounds checks the order of the
// import checks: the weak-key rule on the derived public half first, then
// the key-generation bounds on (f, g).
func TestNewPrivateKeyAppliesWeakKeyRuleThenBounds(t *testing.T) {
	// f = 1, g = 0, F = 0 derives h = 0, the weakest key of all.
	degenerate := make([]byte, PrivateKeySize)
	degenerate[0], degenerate[1] = privateKeyHeader, 0x08
	if _, err := NewPrivateKey(degenerate); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
		t.Errorf("degenerate key: error = %v, want ErrWeakPublicKey", err)
	}
	// A strong public half with (f, g) outside the key-generation bounds.
	oversized := oversizedStrongPrivateKey(t)
	_, err := NewPrivateKey(oversized.Bytes())
	if !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) || errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
		t.Errorf("oversized key: error = %v, want ErrInvalidSecretKey only", err)
	}
	if err := ValidatePublicKey(oversized.PublicKey().Bytes()); err != nil {
		t.Errorf("oversized key's public half should pass the rule: %v", err)
	}
}

// --- shared vectors ----------------------------------------------------------

type weakPublicKeyVector struct {
	Name            string `json:"name"`
	PK              string `json:"pk"`
	Expected        string `json:"expected"`
	Multiplier      int    `json:"multiplier"`
	SquaredNorm     uint64 `json:"squaredNorm"`
	ForgeryVerifies *bool  `json:"forgeryVerifies"`
	Note            string `json:"note,omitempty"`
}

type weakPrivateKeyVector struct {
	Name     string `json:"name"`
	SK       string `json:"sk"`
	Expected string `json:"expected"`
	Note     string `json:"note,omitempty"`
}

type weakKeyVectorFile struct {
	Description      string                 `json:"description"`
	MultiplierBound  int                    `json:"multiplierBound"`
	SquaredNormBound uint64                 `json:"squaredNormBound"`
	PublicKeys       []weakPublicKeyVector  `json:"publicKeys"`
	PrivateKeys      []weakPrivateKeyVector `json:"privateKeys"`
}

const weakKeyVectorsFile = "weak_public_key_vectors.json"

// boolPtr returns a pointer to b, for the optional forgeryVerifies field.
func boolPtr(b bool) *bool { return &b }

// buildWeakKeyVectors constructs the shared vectors. Regenerate the file with
// FALCON_WRITE_WEAK_VECTORS=1 go test -run TestWeakPublicKeyVectors ./crypto/internal/falcon1024/
func buildWeakKeyVectors(t *testing.T) weakKeyVectorFile {
	t.Helper()
	message := []byte("falcon-1024 weak public key vectors")
	honest := testPrivateKey(t)
	a := seededSmallPolynomial("ratio numerator", 600)
	sparseA := seededSmallPolynomial("sparse divisor numerator", 3)
	var sparseB smallPolynomial
	sparseB[0], sparseB[3], sparseB[7] = 1, -1, 1

	type pkCase struct {
		name    string
		h       ringElement
		forgery bool // record whether the two-dimensional rounding forgery verifies
		note    string
	}
	cases := []pkCase{
		{"generated key (seed 0..47)", mustDecode(t, honest.PublicKey().Bytes()), true, "control: the constant-key forgery fails under an honest key"},
		{"h = 0", ringElement{}, true, "degenerate; s1 = c0 is never short"},
		{"constant 1", constantPolynomial(1), true, "lattice vector (-1, 1) is too short for rounding to land inside the bound; structured all the same"},
		{"constant 13", constantPolynomial(13), true, "just below the forgeable window"},
		{"constant 14", constantPolynomial(14), true, "low edge of the forgeable window; success depends on the message"},
		{"constant 20", constantPolynomial(20), true, "inside the window with margin"},
		{"constant 111", constantPolynomial(111), true, "about sqrt(q); the balanced case"},
		{"constant 907", constantPolynomial(907), true, "high edge of the window for c = 1; success depends on the message"},
		{"constant 2000", constantPolynomial(2000), true, "caught at c = 1; 6*2000 = -289 mod q gives the forger an even shorter basis"},
		{"constant 6145 (2^-1 mod q)", constantPolynomial(6145), true, "2*h = 1: lattice vector (-1, 2)"},
		{"constant 12288 (-1 mod q)", constantPolynomial(12288), true, "lattice vector (1, 1)"},
		{"monomial 111 x^777", monomialPolynomial(111, 777), true, "rotation of constant 111"},
		{"small random polynomial, |coeff| <= 20", mustSmall(t, seededSmallPolynomial("small key", 20)), false, "c = 1"},
		{"a / 907, |a_i| <= 600", ratioPolynomial(t, a, constantSmallPolynomial(907)), false, "largest multiplier inside the forgeable window"},
		{"a / 1024, |a_i| <= 600", ratioPolynomial(t, a, constantSmallPolynomial(1024)), false, "last multiplier the rule scans"},
		{"a / 1025, |a_i| <= 600", ratioPolynomial(t, a, constantSmallPolynomial(1025)), false, "one past the scan; N > 1025^2 is outside the forgeable window"},
		{"random direction, ||h||^2 = 2^30 - 1", polynomialWithSquaredNorm(t, "boundary weak", weakKeySquaredNormBound-1), false, "boundary of the c = 1 test, weak side"},
		{"random direction, ||h||^2 = 2^30", polynomialWithSquaredNorm(t, "boundary strong", weakKeySquaredNormBound), false, "boundary of the c = 1 test, strong side"},
		{"a / (1 - x^3 + x^7), |a_i| <= 3", ratioPolynomial(t, sparseA, sparseB), false, "known gap: a sparse non-integer divisor is not scanned"},
	}

	file := weakKeyVectorFile{
		Description: "Falcon-1024 weak public key rule: with h centred in (-q/2, q/2], the key is weak if for some integer c in [1, multiplierBound] " +
			"the squared norm of the centred coefficients of c*h, plus c^2, is at most squaredNormBound. " +
			"multiplier and squaredNorm give the first such c and ||c*h||^2 (0, 0 when strong). forgeryVerifies, where set, records whether " +
			"a signature produced from the key alone, by rounding the message hash against the reduced two-dimensional lattice of a constant or " +
			"monomial key, is accepted by the primitive verifier. privateKeys carry the verdict a private-key import must reach: valid, " +
			"weak (the public half fails the rule) or invalid (the key-generation bounds or the NTRU equation f*G - g*F = q fail). " +
			"Every QRL client must reach the same verdicts.",
		MultiplierBound:  weakKeyMultiplierBound,
		SquaredNormBound: weakKeySquaredNormBound,
	}
	for _, tc := range cases {
		c, norm := weakPublicKeyMultiplier(tc.h)
		v := weakPublicKeyVector{Name: tc.name, PK: hex.EncodeToString(encodePublic(t, tc.h)), Multiplier: c, SquaredNorm: norm, Note: tc.note}
		if c != 0 {
			v.Expected = "weak"
		} else {
			v.Expected = "strong"
		}
		if tc.forgery {
			v.ForgeryVerifies = boolPtr(roundingForgeryVerifies(t, tc.h, message))
		}
		file.PublicKeys = append(file.PublicKeys, v)
	}

	degenerate := make([]byte, PrivateKeySize)
	degenerate[0], degenerate[1] = privateKeyHeader, 0x08
	honestBytes := honest.Bytes()
	file.PrivateKeys = []weakPrivateKeyVector{
		{"generated key (seed 0..47)", hex.EncodeToString(honestBytes), "valid", ""},
		{"f = 1, g = 0, F = 0", hex.EncodeToString(degenerate), "weak", "derives h = 0; refused before the key-generation bounds"},
		{"(f, g) outside the squared-norm bound, strong public half", hex.EncodeToString(oversizedStrongPrivateKey(t).Bytes()), "invalid", "passes the weak-key rule, fails the key-generation bounds"},
		{"generated key with F replaced by x*F", hex.EncodeToString(substituteF(t, honestBytes, shiftedF)), "invalid", "derives the correct public key; f*G - g*F = x*q, so signing could never pass the norm check"},
		{"generated key with F replaced by -F", hex.EncodeToString(substituteF(t, honestBytes, negatedF)), "invalid", "derives the correct public key; f*G - g*F = -q"},
		{"generated key with F replaced by f", hex.EncodeToString(substituteF(t, honestBytes, fAsF)), "invalid", "derives the correct public key; f*G - g*F = 0, so the sampler would never produce a sample"},
	}
	return file
}

// roundingForgeryVerifies runs the two-dimensional rounding forgery against
// h: the monomial version when h has a single nonzero coefficient, otherwise
// the constant-111 rounding as a control that fails under any other key.
func roundingForgeryVerifies(t *testing.T, h ringElement, message []byte) bool {
	t.Helper()
	var k int32
	var j, nonzero int
	for idx, coeff := range h {
		if coeff != 0 {
			k, j = int32(coeff), idx
			nonzero++
		}
	}
	if nonzero == 1 {
		return forgeUnderMonomial(t, k, j, message)
	}
	pub, err := newPublicKeyFromH(h)
	if err != nil {
		t.Fatal(err)
	}
	return forgeConstantUnderKey(t, &pub, 111, message)
}

// mustDecode parses an encoded public key or fails the test.
func mustDecode(t *testing.T, pk []byte) ringElement {
	t.Helper()
	h, err := pkDecode(pk)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// mustSmall lifts a small polynomial to its representative with
// coefficients in [0, q).
func mustSmall(t *testing.T, p smallPolynomial) ringElement {
	t.Helper()
	var h ringElement
	for i := range h {
		h[i] = fieldFromSmall(p[i])
	}
	return h
}

// TestWeakPublicKeyVectors rebuilds the shared vectors, checks that the
// stored file matches field for field, and re-derives every verdict,
// multiplier, norm and forgery flag from the stored bytes alone. With
// FALCON_WRITE_WEAK_VECTORS=1 it rewrites the file first.
func TestWeakPublicKeyVectors(t *testing.T) {
	built := buildWeakKeyVectors(t)
	path := filepath.Join("testdata", weakKeyVectorsFile)
	if os.Getenv("FALCON_WRITE_WEAK_VECTORS") == "1" {
		data, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
	}

	stored := testutil.ReadJSON[weakKeyVectorFile](t, "testdata", weakKeyVectorsFile)
	if stored.MultiplierBound != weakKeyMultiplierBound || stored.SquaredNormBound != weakKeySquaredNormBound {
		t.Fatalf("vector file bounds %d / %d do not match the rule %d / %d", stored.MultiplierBound, stored.SquaredNormBound, weakKeyMultiplierBound, weakKeySquaredNormBound)
	}
	if len(stored.PublicKeys) != len(built.PublicKeys) || len(stored.PrivateKeys) != len(built.PrivateKeys) {
		t.Fatalf("vector file holds %d/%d vectors, this test builds %d/%d; regenerate with FALCON_WRITE_WEAK_VECTORS=1",
			len(stored.PublicKeys), len(stored.PrivateKeys), len(built.PublicKeys), len(built.PrivateKeys))
	}

	message := []byte("falcon-1024 weak public key vectors")
	for i, v := range stored.PublicKeys {
		t.Run(v.Name, func(t *testing.T) {
			if field := vectorDifference(v, built.PublicKeys[i]); field != "" {
				t.Fatalf("stored %s differs from the construction; regenerate with FALCON_WRITE_WEAK_VECTORS=1", field)
			}
			pk, err := hex.DecodeString(v.PK)
			if err != nil {
				t.Fatal(err)
			}
			h, err := pkDecode(pk)
			if err != nil {
				t.Fatal(err)
			}
			c, norm := weakPublicKeyMultiplier(h)
			weak := c != 0
			if weak != (v.Expected == "weak") || c != v.Multiplier || norm != v.SquaredNorm {
				t.Fatalf("verdict (weak=%v, c=%d, norm=%d) differs from the vector (%s, c=%d, norm=%d)", weak, c, norm, v.Expected, v.Multiplier, v.SquaredNorm)
			}
			_, err = NewPublicKey(pk)
			if weak != errors.Is(err, cryptoerrors.ErrWeakPublicKey) || (!weak && err != nil) {
				t.Fatalf("NewPublicKey error = %v for a %s key", err, v.Expected)
			}
			if v.ForgeryVerifies != nil {
				if got := roundingForgeryVerifies(t, h, message); got != *v.ForgeryVerifies {
					t.Fatalf("forgery verifies = %v, vector says %v", got, *v.ForgeryVerifies)
				}
			}
		})
	}
	for i, v := range stored.PrivateKeys {
		t.Run(v.Name, func(t *testing.T) {
			if v != built.PrivateKeys[i] {
				t.Fatalf("stored vector differs from the construction; regenerate with FALCON_WRITE_WEAK_VECTORS=1")
			}
			sk, err := hex.DecodeString(v.SK)
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewPrivateKey(sk)
			switch v.Expected {
			case "valid":
				if err != nil {
					t.Fatalf("NewPrivateKey: %v", err)
				}
			case "weak":
				if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
					t.Fatalf("NewPrivateKey error = %v, want ErrWeakPublicKey", err)
				}
			case "invalid":
				if !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) || errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
					t.Fatalf("NewPrivateKey error = %v, want ErrInvalidSecretKey only", err)
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expected)
			}
		})
	}
}

// vectorDifference names the first field in which two public-key vectors
// differ, comparing forgeryVerifies by value rather than pointer, or returns
// "" when they match.
func vectorDifference(stored, built weakPublicKeyVector) string {
	switch {
	case stored.Name != built.Name:
		return "name"
	case stored.PK != built.PK:
		return "pk"
	case stored.Expected != built.Expected:
		return "expected"
	case stored.Multiplier != built.Multiplier:
		return "multiplier"
	case stored.SquaredNorm != built.SquaredNorm:
		return "squaredNorm"
	case (stored.ForgeryVerifies == nil) != (built.ForgeryVerifies == nil):
		return "forgeryVerifies"
	case stored.ForgeryVerifies != nil && *stored.ForgeryVerifies != *built.ForgeryVerifies:
		return "forgeryVerifies"
	case stored.Note != built.Note:
		return "note"
	}
	return ""
}

// TestVectorDifference checks that the stored-vector comparison notices a
// change in any one field, including the pointer-valued forgery flag.
func TestVectorDifference(t *testing.T) {
	base := weakPublicKeyVector{Name: "n", PK: "0a", Expected: "weak", Multiplier: 1, SquaredNorm: 2, ForgeryVerifies: boolPtr(true), Note: "x"}
	if got := vectorDifference(base, base); got != "" {
		t.Errorf("identical vectors reported %q", got)
	}
	copyWith := func(mutate func(v *weakPublicKeyVector)) weakPublicKeyVector {
		v := base
		v.ForgeryVerifies = boolPtr(*base.ForgeryVerifies)
		mutate(&v)
		return v
	}
	for want, mutate := range map[string]func(v *weakPublicKeyVector){
		"name":        func(v *weakPublicKeyVector) { v.Name = "m" },
		"pk":          func(v *weakPublicKeyVector) { v.PK = "0b" },
		"expected":    func(v *weakPublicKeyVector) { v.Expected = "strong" },
		"multiplier":  func(v *weakPublicKeyVector) { v.Multiplier = 2 },
		"squaredNorm": func(v *weakPublicKeyVector) { v.SquaredNorm = 3 },
		"note":        func(v *weakPublicKeyVector) { v.Note = "y" },
	} {
		if got := vectorDifference(base, copyWith(mutate)); got != want {
			t.Errorf("changed %s: reported %q", want, got)
		}
	}
	if got := vectorDifference(base, copyWith(func(v *weakPublicKeyVector) { v.ForgeryVerifies = nil })); got != "forgeryVerifies" {
		t.Errorf("flag dropped: reported %q", got)
	}
	if got := vectorDifference(base, copyWith(func(v *weakPublicKeyVector) { *v.ForgeryVerifies = false })); got != "forgeryVerifies" {
		t.Errorf("flag flipped: reported %q", got)
	}
	if got := vectorDifference(base, copyWith(func(v *weakPublicKeyVector) { v.ForgeryVerifies = boolPtr(true) })); got != "" {
		t.Errorf("equal flag behind a different pointer reported %q", got)
	}
}

// forgeConstantUnderKey applies the constant-k rounding to an arbitrary key,
// which succeeds only if the key really is k (the honest control).
func forgeConstantUnderKey(t *testing.T, pub *PublicKey, k int32, message []byte) bool {
	t.Helper()
	var nonce [nonceSize]byte
	hash := sha3.NewSHAKE256()
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write(message)
	c0 := hashToPoint(hash)
	b1, b2 := gaussReduce(int64(k))
	var s2 smallPolynomial
	for m, c := range c0 {
		v := int64(c)
		if v > q/2 {
			v -= q
		}
		_, y := babaiResidual(b1, b2, [2]float64{float64(v), 0})
		s2[m] = int32(y)
	}
	sig, err := detachedSignatureEncode(nonce, s2)
	if err != nil {
		return false
	}
	return Verify(pub, message, sig) == nil
}

// BenchmarkValidatePublicKey measures the rule on a generated key, the
// common case, where every multiplier exits early.
func BenchmarkValidatePublicKey(b *testing.B) {
	seed := make([]byte, SeedSize)
	priv, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		b.Fatal(err)
	}
	pk := priv.PublicKey().Bytes()
	b.ResetTimer()
	for range b.N {
		if err := ValidatePublicKey(pk); err != nil {
			b.Fatal(err)
		}
	}
}

// ExampleValidatePublicKey shows that a generated key passes the rule.
func ExampleValidatePublicKey() {
	seed := make([]byte, SeedSize)
	priv, _ := NewPrivateKeyFromSeed(seed)
	fmt.Println(ValidatePublicKey(priv.PublicKey().Bytes()) == nil)
	// Output: true
}
