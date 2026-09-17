package falcon1024

import (
	"slices"
	"testing"
)

// These modP vectors exercise the Falcon reference modp_* arithmetic over the
// same small-prime table used by NTRU/CRT. Expected values were generated from
// the reference formulas with R = 2^31 and bit-reversed roots, not from the Go
// implementation.
// Source: https://falcon-sign.info/impl/keygen.c.html

func TestModPSet(t *testing.T) {
	p := smallPrimes[0].p
	for _, tc := range []struct {
		name string
		x    int32
		want uint32
	}{
		{name: "zero", x: 0, want: 0},
		{name: "positive", x: 123456789, want: 123456789},
		{name: "negative one", x: -1, want: p - 1},
		{name: "negative bound", x: -127, want: p - 127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modPSet(tc.x, p); got != tc.want {
				t.Fatalf("modPSet = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestModPNorm(t *testing.T) {
	p := smallPrimes[0].p
	for _, tc := range []struct {
		name string
		x    uint32
		want int32
	}{
		{name: "zero", x: 0, want: 0},
		{name: "small positive", x: 123456789, want: 123456789},
		{name: "positive edge", x: p >> 1, want: int32(p >> 1)},
		{name: "negative edge", x: (p >> 1) + 1, want: -1073736704},
		{name: "negative one", x: p - 1, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modPNorm(tc.x, p); got != tc.want {
				t.Fatalf("modPNorm = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestModPAdd(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    uint32
		a    uint32
		b    uint32
		want uint32
	}{
		{
			name: "small prime 0",
			p:    smallPrimes[0].p,
			a:    5,
			b:    7,
			want: 12,
		},
		{
			name: "wrap prime 0",
			p:    smallPrimes[0].p,
			a:    2147473407,
			b:    5,
			want: 3,
		},
		{
			name: "max prime 1",
			p:    smallPrimes[1].p,
			a:    2147389440,
			b:    2147389440,
			want: 2147389439,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modPAdd(tc.a, tc.b, tc.p); got != tc.want {
				t.Fatalf("modPAdd = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestModPSub(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    uint32
		a    uint32
		b    uint32
		want uint32
	}{
		{
			name: "small prime 0",
			p:    smallPrimes[0].p,
			a:    5,
			b:    7,
			want: 2147473407,
		},
		{
			name: "wrap prime 0",
			p:    smallPrimes[0].p,
			a:    2147473407,
			b:    5,
			want: 2147473402,
		},
		{
			name: "max prime 1",
			p:    smallPrimes[1].p,
			a:    2147389440,
			b:    2147389440,
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modPSub(tc.a, tc.b, tc.p); got != tc.want {
				t.Fatalf("modPSub = %d, want %d", got, tc.want)
			}
		})
	}
}

type modPRxCase struct {
	x    int
	want uint32
}

type modPMulCase struct {
	a, b uint32
	want uint32
}

type modPDivCase struct {
	a, b uint32
	want uint32
}

var modPMontgomeryTestCases = []struct {
	name       string
	primeIndex int
	wantP0i    uint32
	wantR      uint32
	wantR2     uint32
	wantRx     []modPRxCase
	mul        []modPMulCase
	div        []modPDivCase
}{
	{
		name:       "prime 0",
		primeIndex: 0,
		wantP0i:    2042615807,
		wantR:      10239,
		wantR2:     104837121,
		wantRx: []modPRxCase{
			{x: 1, want: 10239},
			{x: 2, want: 104837121},
			{x: 5, want: 546337913},
			{x: 209, want: 1926030416},
			{x: 1024, want: 1858646498},
		},
		mul: []modPMulCase{
			{a: 123456789, b: 987654321, want: 588659901},
			{a: 2147473407, b: 3, want: 629204046},
			{a: 1, b: 1, want: 2042606068},
			{a: 104837121, b: 383167813, want: 1968792473},
		},
		div: []modPDivCase{
			{a: 5, b: 7, want: 1227127663},
			{a: 123456789, b: 987654321, want: 464434420},
			{a: 2147473407, b: 3, want: 715824469},
			{a: 104837121, b: 383167813, want: 1485738006},
		},
	},
	{
		name:       "prime 1",
		primeIndex: 1,
		wantP0i:    1862176767,
		wantR:      94207,
		wantR2:     285401085,
		wantRx: []modPRxCase{
			{x: 1, want: 94207},
			{x: 2, want: 285401085},
			{x: 5, want: 1467853668},
			{x: 209, want: 1394546252},
			{x: 1024, want: 877988126},
		},
		mul: []modPMulCase{
			{a: 123456789, b: 987654321, want: 710110895},
			{a: 2147389439, b: 3, want: 1711766190},
			{a: 1, b: 1, want: 1862095076},
			{a: 285401085, b: 211808905, want: 338827563},
		},
		div: []modPDivCase{
			{a: 5, b: 7, want: 613539841},
			{a: 123456789, b: 987654321, want: 220855656},
			{a: 2147389439, b: 3, want: 1431592960},
			{a: 285401085, b: 211808905, want: 348056158},
		},
	},
	{
		name:       "last nonzero prime",
		primeIndex: len(smallPrimes) - 2,
		wantP0i:    2098206719,
		wantR:      11528191,
		wantR2:     39197941,
		wantRx: []modPRxCase{
			{x: 1, want: 11528191},
			{x: 2, want: 39197941},
			{x: 5, want: 1185998780},
			{x: 209, want: 1404733308},
			{x: 1024, want: 42721858},
		},
		mul: []modPMulCase{
			{a: 123456789, b: 987654321, want: 543127818},
			{a: 2135955455, b: 3, want: 294074394},
			{a: 1, b: 1, want: 2086943058},
			{a: 39197941, b: 538755304, want: 439707803},
		},
		div: []modPDivCase{
			{a: 5, b: 7, want: 1525682470},
			{a: 123456789, b: 987654321, want: 1827225845},
			{a: 2135955455, b: 3, want: 1423970304},
			{a: 39197941, b: 538755304, want: 1959601019},
		},
	},
}

func TestModPMontgomeryConstants(t *testing.T) {
	for _, tc := range modPMontgomeryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			p := smallPrimes[tc.primeIndex].p
			p0i := modPNInv31(p)
			if p0i != tc.wantP0i {
				t.Fatalf("modPNInv31 = %d, want %d", p0i, tc.wantP0i)
			}
			if got := modPR(p); got != tc.wantR {
				t.Fatalf("modPR = %d, want %d", got, tc.wantR)
			}
			if got := modPR2(p, p0i); got != tc.wantR2 {
				t.Fatalf("modPR2 = %d, want %d", got, tc.wantR2)
			}
			derived := smallPrimeDerivedValues[tc.primeIndex]
			if derived.p0i != p0i {
				t.Fatalf("cached p0i = %d, want %d", derived.p0i, p0i)
			}
			if derived.r2 != tc.wantR2 {
				t.Fatalf("cached r2 = %d, want %d", derived.r2, tc.wantR2)
			}
		})
	}
}

func TestModPMontyMul(t *testing.T) {
	for _, tc := range modPMontgomeryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			p := smallPrimes[tc.primeIndex].p
			p0i := modPNInv31(p)
			for _, mul := range tc.mul {
				if got := modPMontyMul(mul.a, mul.b, p, p0i); got != mul.want {
					t.Fatalf("modPMontyMul(%d, %d) = %d, want %d", mul.a, mul.b, got, mul.want)
				}
			}
		})
	}
}

func TestModPRx(t *testing.T) {
	for _, tc := range modPMontgomeryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			p := smallPrimes[tc.primeIndex].p
			p0i := modPNInv31(p)
			r2 := modPR2(p, p0i)
			for _, wantRx := range tc.wantRx {
				if got := modPRx(wantRx.x, p, p0i, r2); got != wantRx.want {
					t.Fatalf("modPRx(%d) = %d, want %d", wantRx.x, got, wantRx.want)
				}
			}
		})
	}
}

func TestModPDiv(t *testing.T) {
	for _, tc := range modPMontgomeryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			p := smallPrimes[tc.primeIndex].p
			p0i := modPNInv31(p)
			r := modPR(p)
			for _, div := range tc.div {
				if got := modPDiv(div.a, div.b, p, p0i, r); got != div.want {
					t.Fatalf("modPDiv(%d, %d) = %d, want %d", div.a, div.b, got, div.want)
				}
			}
		})
	}
}

func TestModPMkgm2(t *testing.T) {
	p := smallPrimes[0].p
	p0i := modPNInv31(p)

	gm := make([]uint32, 8)
	igm := make([]uint32, 8)
	modPMkgm2(gm, igm, 3, smallPrimes[0].g, p, p0i)

	requireEqualWords(t, "modPMkgm2 gm", gm, []uint32{
		10239, 1211775442, 844192849, 380966363,
		1642906936, 510722630, 1508861108, 414755385,
	})
	requireEqualWords(t, "modPMkgm2 igm", igm, []uint32{
		10239, 935697967, 1766507046, 1303280560,
		1732718024, 638612301, 1636750779, 504566473,
	})
}

func TestModPNTT2Ext(t *testing.T) {
	p := smallPrimes[0].p
	p0i := modPNInv31(p)
	gm := make([]uint32, 8)
	igm := make([]uint32, 8)
	modPMkgm2(gm, igm, 3, smallPrimes[0].g, p, p0i)

	t.Run("strided", func(t *testing.T) {
		const sentinel = uint32(0x5A5A5A5A)
		a := []uint32{
			1, sentinel, 2, sentinel, 3, sentinel, 4, sentinel,
			5, sentinel, 6, sentinel, 7, sentinel, 8,
		}

		modPNTT2Ext(a, 2, gm, 3, p, p0i)
		requireEqualWords(t, "modPNTT2Ext", a, []uint32{
			1939742775, sentinel, 1889065586, sentinel,
			1695103822, sentinel, 327325878, sentinel,
			2078796089, sentinel, 1251355496, sentinel,
			1880810079, sentinel, 1822640737,
		})

		modPINTT2Ext(a, 2, igm, 3, p, p0i)
		requireEqualWords(t, "modPINTT2Ext", a, []uint32{
			1, sentinel, 2, sentinel, 3, sentinel, 4, sentinel,
			5, sentinel, 6, sentinel, 7, sentinel, 8,
		})
	})

	t.Run("forward logn 0", func(t *testing.T) {
		a := []uint32{12345, 67890}
		want := slices.Clone(a)

		modPNTT2Ext(a, 2, nil, 0, p, p0i)
		requireEqualWords(t, "modPNTT2Ext logn 0", a, want)
	})

	t.Run("inverse logn 0", func(t *testing.T) {
		a := []uint32{12345, 67890}
		want := slices.Clone(a)

		modPINTT2Ext(a, 2, nil, 0, p, p0i)
		requireEqualWords(t, "modPINTT2Ext logn 0", a, want)
	})
}

func TestModPPolyRecRes(t *testing.T) {
	p := smallPrimes[0].p
	p0i := modPNInv31(p)
	r2 := modPR2(p, p0i)

	f := []uint32{
		3, 5,
		7, 11,
		smallPrimes[0].p - 2, smallPrimes[0].p - 3,
		123456789, 987654321,
	}
	modPPolyRecRes(f, 3, p, p0i, r2)

	requireEqualWords(t, "modPPolyRecRes", f, []uint32{
		15, 77, 6, 1478340685,
		smallPrimes[0].p - 2, smallPrimes[0].p - 3,
		123456789, 987654321,
	})
}
