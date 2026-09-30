package falcon1024

import (
	"crypto/sha3"
	"math"
	"math/big"
	"slices"
	"strconv"
	"testing"
)

// gaussian0Distribution is the expected half-Gaussian distribution scaled by
// 2^72, as specified in Prest, Ricosset and Rossi, "Simple, Fast and
// Constant-Time Gaussian Sampling over the Integers for Falcon". Entry i is
// the number of 72-bit inputs that must map to output i; the entries sum to
// exactly 2^72.
var gaussian0Distribution = [...]string{
	"1697680241746640300030",
	"1459943456642912959616",
	"928488355018011056515",
	"436693944817054414619",
	"151893140790369201013",
	"39071441848292237840",
	"7432604049020375675",
	"1045641569992574730",
	"108788995549429682",
	"8370422445201343",
	"476288472308334",
	"20042553305308",
	"623729532807",
	"14354889437",
	"244322621",
	"3075302",
	"28626",
	"197",
	"1",
}

func TestGaussian0SampleDistribution(t *testing.T) {
	// gaussian0Sample reads a 72-bit value and walks a CDT, so feeding it the
	// lowest and highest value of every range pins the whole table.
	check := func(x *big.Int, want int) {
		t.Helper()

		var raw [9]byte
		x.FillBytes(raw[:])
		slices.Reverse(raw[:]) // the PRNG yields the value in little-endian order

		if got := gaussian0Sample(newSamplerPRNGFromBytes(raw[:])); got != want {
			t.Fatalf("gaussian0Sample(%#x) = %d, want %d", x, got, want)
		}
	}

	one := big.NewInt(1)
	limit := new(big.Int).Lsh(one, 72)

	// The bottom range holds the single value 0 and maps to the largest output.
	top := new(big.Int)
	check(top, len(gaussian0Distribution)-1)

	for i := len(gaussian0Distribution) - 2; i >= 0; i-- {
		size, ok := new(big.Int).SetString(gaussian0Distribution[i], 10)
		if !ok {
			t.Fatalf("invalid distribution entry %d", i)
		}

		check(new(big.Int).Add(top, one), i)
		top.Add(top, size)
		if top.Cmp(limit) >= 0 {
			t.Fatalf("distribution overflows 2^72 at entry %d", i)
		}
		check(top, i)
	}

	// top is now the highest value of the highest range, i.e. 2^72-1.
	if top.Add(top, one).Cmp(limit) != 0 {
		t.Fatal("distribution does not sum to 2^72")
	}
}

func TestSampleFFTPointChiSquare(t *testing.T) {
	// For 21 centers between -1 and +1, draw 100000 samples and run a
	// chi-square goodness-of-fit test against the discrete Gaussian
	//
	//	P(z) = K * exp(-(z-mu)^2 / (2*sigma^2))
	//
	// sampleFFTPoint is bound to the Falcon-1024 sigma_min, which only changes
	// the acceptance rate of the rejection step, not the output distribution.
	// The seed is fixed, which makes the test deterministic.
	const (
		maxDev     = 30
		numSamples = 100000
	)

	// Chi-square critical values for alpha = 0.01, by degrees of freedom.
	criticalValues := map[int]float64{
		13: 27.688,
		14: 29.141,
	}

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("test sampler"))
	prng := newSamplerPRNG(rng)

	isigma := fpr(10) / fpr(17)
	mu := fpr(-1)
	muInc := fpr(1) / fpr(10)

	for i := range 21 {
		name := "mu-" + strconv.Itoa(i)
		center := int(fprTrunc(mu))

		var observed [2*maxDev + 1]int
		for range numSamples {
			z := int(sampleFFTPoint(prng, mu, isigma)) - center
			if z < -maxDev || z > maxDev {
				t.Fatalf("%s: out-of-range sampled value: %d", name, z)
			}
			observed[z+maxDev]++
		}

		var expected [2*maxDev + 1]float64
		var sum float64
		for z := -maxDev; z <= maxDev; z++ {
			d := (float64(z+center) - float64(mu)) * float64(isigma)
			expected[z+maxDev] = math.Exp(-0.5 * d * d)
			sum += expected[z+maxDev]
		}
		for z := range expected {
			expected[z] *= numSamples / sum
		}

		// Group both tails into bins with an expected count of at least 5.
		var expectedLow, expectedHigh float64
		zmin := -maxDev
		for ; ; zmin++ {
			expectedLow += expected[zmin+maxDev]
			if expectedLow >= 5 {
				break
			}
		}
		zmax := maxDev
		for ; ; zmax-- {
			expectedHigh += expected[zmax+maxDev]
			if expectedHigh >= 5 {
				break
			}
		}

		var observedLow, observedHigh int
		for z := -maxDev; z <= zmin; z++ {
			observedLow += observed[z+maxDev]
		}
		for z := zmax; z <= maxDev; z++ {
			observedHigh += observed[z+maxDev]
		}

		term := func(observed int, expected float64) float64 {
			d := float64(observed) - expected
			return d * d / expected
		}
		chi := term(observedLow, expectedLow) + term(observedHigh, expectedHigh)
		for z := zmin + 1; z <= zmax-1; z++ {
			chi += term(observed[z+maxDev], expected[z+maxDev])
		}

		df := zmax - zmin
		critical, ok := criticalValues[df]
		if !ok {
			t.Fatalf("%s: unexpected number of classes: %d", name, df+1)
		}
		t.Logf("%s: mu = %+.1f, df = %d, chi-square = %.2f (critical %.2f)", name, float64(mu), df, chi, critical)
		if chi >= critical {
			t.Fatalf("%s: chi-square test failed: %.2f >= %.2f", name, chi, critical)
		}

		mu += muInc
	}
}
