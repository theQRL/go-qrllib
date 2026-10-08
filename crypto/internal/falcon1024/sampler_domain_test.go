package falcon1024

import (
	"crypto/sha3"
	"testing"
)

// samplerDomain summarizes the leaves of a private key's LDL tree in terms of
// the two quantities that sampleFFTPoint derives from a leaf, which holds
// isigma = 1/sigma' for one pair of samples:
//
//	ccs = sigmaMin1024 * isigma
//	dss = 0.5 * isigma * isigma
//
// The sampler is only defined for sigma_min <= sigma' <= sigma_max, which
// means ccs <= 1 and dss >= inv2SqrSigma0. fprExpmP63 relies on it: it converts
// ccs*2^63 and x*2^63 to int64, where x >= 0 only if dss >= inv2SqrSigma0. The
// first conversion is out of range from ccs = 1 on, the second one for x < 0,
// and Go leaves the result of such conversions implementation-dependent.
type samplerDomain struct {
	leaves        int
	maxCCS        fpr
	minDSS        fpr
	ccsViolations int // leaves with ccs >= 1
	dssViolations int // leaves with dss < inv2SqrSigma0
}

func (d *samplerDomain) add(isigma fpr) {
	ccs := sigmaMin1024 * isigma
	dss := 0.5 * isigma * isigma

	if d.leaves == 0 || ccs > d.maxCCS {
		d.maxCCS = ccs
	}
	if d.leaves == 0 || dss < d.minDSS {
		d.minDSS = dss
	}
	if ccs >= 1 {
		d.ccsViolations++
	}
	if dss < inv2SqrSigma0 {
		d.dssViolations++
	}
	d.leaves++
}

// forEachLDLLeaf visits the leaves of an LDL tree in the layout produced by
// ffLDLFFT: a node of degree 2^logn holds 2^logn values followed by its two
// subtrees, and a node of degree 1 is a leaf.
func forEachLDLLeaf(tree []fpr, logn int, visit func(leaf fpr)) {
	if logn == 0 {
		visit(tree[0])
		return
	}

	degree := 1 << logn
	forEachLDLLeaf(tree[degree:], logn-1, visit)
	forEachLDLLeaf(tree[degree+ffLDLTreeSize(logn-1):], logn-1, visit)
}

func measureSamplerDomain(t *testing.T, priv *PrivateKey) samplerDomain {
	t.Helper()

	var d samplerDomain
	forEachLDLLeaf(priv.tree[:], logN, d.add)
	if d.leaves != n {
		t.Fatalf("LDL tree has %d leaves, want %d", d.leaves, n)
	}
	return d
}

func TestGeneratedKeysStayInSamplerDomain(t *testing.T) {
	// Key generation only accepts f and g whose Gram-Schmidt norm is at most
	// 1.17*sqrt(q). That bound is what keeps every leaf of the LDL tree inside
	// the domain of the sampler, and with it the conversions in fprExpmP63 in
	// range. Signing does not check it again, so this test does: a change to
	// the key generation bounds, or a new way to load private keys, must not
	// produce keys outside of the domain.
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("sampler domain"))

	var maxCCS, minDSS fpr
	for i := range 32 {
		priv, err := keygen(&PrivateKey{}, rng)
		if err != nil {
			t.Fatal(err)
		}

		d := measureSamplerDomain(t, priv)
		if d.ccsViolations != 0 {
			t.Fatalf("key %d: %d leaves with ccs >= 1 (max %v)", i, d.ccsViolations, d.maxCCS)
		}
		if d.dssViolations != 0 {
			t.Fatalf("key %d: %d leaves with dss < %v (min %v)", i, d.dssViolations, inv2SqrSigma0, d.minDSS)
		}

		if i == 0 || d.maxCCS > maxCCS {
			maxCCS = d.maxCCS
		}
		if i == 0 || d.minDSS < minDSS {
			minDSS = d.minDSS
		}
	}
	t.Logf("max ccs = %v (limit 1), min dss = %v (limit %v)", maxCCS, minDSS, inv2SqrSigma0)
}

func TestFixedKeyLeavesSamplerDomain(t *testing.T) {
	// The fixed ntru*1024Hex key, which several tests sign with, is not a key
	// that key generation would produce: some of its leaves are outside of
	// the domain of the sampler, in both directions. Signatures made with it
	// are valid, but their exact value depends on how out-of-range conversions
	// behave, so it may differ between architectures and implementations.
	// Tests must not pin it. This also shows that measureSamplerDomain is able
	// to find violations.
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

	d := measureSamplerDomain(t, priv)
	t.Logf("%d leaves with ccs >= 1 (max %v), %d leaves with dss < %v (min %v)",
		d.ccsViolations, d.maxCCS, d.dssViolations, inv2SqrSigma0, d.minDSS)
	if d.ccsViolations == 0 {
		t.Fatal("fixed key has no leaf with ccs >= 1")
	}
	if d.dssViolations == 0 {
		t.Fatalf("fixed key has no leaf with dss < %v", inv2SqrSigma0)
	}
}
