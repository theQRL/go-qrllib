package falcon1024

import (
	"math"
	"testing"
)

func TestFFTRoundTrip(t *testing.T) {
	var p fftPolynomial
	for i := range p {
		p[i] = fpr((i % 31) - 15)
	}
	want := p

	fft(p[:], logN)
	inverseFFT(p[:], logN)

	for i := range p {
		if !fprAlmostEqual(p[i], want[i]) {
			t.Fatalf("FFT round trip mismatch at %d: got %v, want %v", i, p[i], want[i])
		}
	}
}

func TestSplitMergeFFTRoundTrip(t *testing.T) {
	var p fftPolynomial
	for i := range p {
		p[i] = fpr((i % 17) - 8)
	}
	fft(p[:], logN)
	want := p

	var even, odd [n / 2]fpr
	splitFFT(even[:], odd[:], p[:], logN)
	mergeFFT(p[:], even[:], odd[:], logN)

	for i := range p {
		if !fprAlmostEqual(p[i], want[i]) {
			t.Fatalf("split/merge FFT mismatch at %d: got %v, want %v", i, p[i], want[i])
		}
	}
}

func TestFFTMul(t *testing.T) {
	const testLogN = 4
	const testN = 1 << testLogN

	var a, b, want [testN]fpr
	for i := range testN {
		a[i] = fpr((i % 7) - 3)
		b[i] = fpr((i % 5) - 2)
	}

	for i := range testN {
		for j := range testN {
			k := i + j
			v := a[i] * b[j]
			if k >= testN {
				want[k-testN] -= v
			} else {
				want[k] += v
			}
		}
	}

	fft(a[:], testLogN)
	fft(b[:], testLogN)
	fftMul(a[:], b[:], testLogN)
	inverseFFT(a[:], testLogN)

	for i := range testN {
		if !fprAlmostEqual(a[i], want[i]) {
			t.Fatalf("fftMul mismatch at %d: got %v, want %v", i, a[i], want[i])
		}
	}
}

func fprAlmostEqual(a, b fpr) bool {
	const tolerance = 1e-9
	return math.Abs(float64(a-b)) <= tolerance
}

func TestSampleFFTPointReferenceVectors(t *testing.T) {
	// Derived from Supporting_Documentation/additional/
	// test-vector-sampler-falcon1024.txt in the Falcon submission package.
	// Source archive: https://falcon-sign.info/falcon-round3.zip
	testCases := []struct {
		name   string
		mu     fpr
		isigma fpr
		random []byte
		want   fpr
	}{
		{
			name:   "sample-0",
			mu:     fpr(0x1.770D850D3A641p+4),
			isigma: fpr(0x1.21A5FD8ACCC85p-1),
			random: samplerZRandomBytes(t,
				"2456D910A6D01FF847", "e5", "ba",
				"9B3A192D03E66EF1B9", "82", "e1",
				"B0AFDD171571B1596A", "f0", "80",
			),
			want: 23,
		},
		{
			name:   "sample-1",
			mu:     fpr(-0x1.626A731D9A0CEp+5),
			isigma: fpr(0x1.21A5FD8ACCC85p-1),
			random: samplerZRandomBytes(t,
				"1570F5400B5D4105A9", "ad", "59",
			),
			want: -41,
		},
		{
			name:   "sample-2",
			mu:     fpr(0x1.C1620A4D30AFDp+5),
			isigma: fpr(0x1.21DB8B291C67Bp-1),
			random: samplerZRandomBytes(t,
				"93155B536586EE894B", "e6", "7f",
			),
			want: 55,
		},
		{
			name:   "sample-3",
			mu:     fpr(-0x1.F5327142A8146p+0),
			isigma: fpr(0x1.21DB8B291C67Bp-1),
			random: samplerZRandomBytes(t,
				"F6F463543FD3932996", "7e", "8e",
			),
			want: -2,
		},
		{
			name:   "sample-4",
			mu:     fpr(0x1.B7B737B5A980Fp+5),
			isigma: fpr(0x1.21EE81DBE3B08p-1),
			random: samplerZRandomBytes(t,
				"4241276FB38918AC52", "5f", "76",
			),
			want: 57,
		},
		{
			name:   "sample-5",
			mu:     fpr(0x1.216B550083480p+2),
			isigma: fpr(0x1.21EE81DBE3B08p-1),
			random: samplerZRandomBytes(t,
				"F5FDCC11F556DA6267", "74", "eb",
				"2DEAE8A40E1BFBD372", "f8", "68",
			),
			want: 2,
		},
		{
			name:   "sample-6",
			mu:     fpr(0x1.ECBC2060B49DEp+3),
			isigma: fpr(0x1.22272ED588AE2p-1),
			random: samplerZRandomBytes(t,
				"6BD800DFE201A3A261", "73", "20",
			),
			want: 17,
		},
		{
			name:   "sample-7",
			mu:     fpr(-0x1.33896EADE02A6p+5),
			isigma: fpr(0x1.22272ED588AE2p-1),
			random: samplerZRandomBytes(t,
				"220100A789EE305BE5", "1e", "fe",
				"66569AF9997C0B1FE5", "a0", "6c",
			),
			want: -40,
		},
		{
			name:   "sample-8",
			mu:     fpr(0x1.2AF7AA0219318p+5),
			isigma: fpr(0x1.223EECB7408ECp-1),
			random: samplerZRandomBytes(t,
				"C2BC576BD87F27B91A", "3f", "97",
			),
			want: 38,
		},
		{
			name:   "sample-9",
			mu:     fpr(-0x1.5A0F9C5A3C9DAp+3),
			isigma: fpr(0x1.223EECB7408ECp-1),
			random: samplerZRandomBytes(t,
				"216758322128F4B7FB", "f2", "49",
			),
			want: -14,
		},
		{
			name:   "sample-10",
			mu:     fpr(-0x1.1CD09D0ED5F08p+3),
			isigma: fpr(0x1.227BBD5B1D49Ep-1),
			random: samplerZRandomBytes(t,
				"ED3DAC498D9354120B", "6d", "18",
			),
			want: -8,
		},
		{
			name:   "sample-11",
			mu:     fpr(-0x1.35A183B130857p+4),
			isigma: fpr(0x1.227BBD5B1D49Ep-1),
			random: samplerZRandomBytes(t,
				"DEC35E48061B08798E", "11", "68",
			),
			want: -19,
		},
		{
			name:   "sample-12",
			mu:     fpr(-0x1.9A99F3B79E3F8p+3),
			isigma: fpr(0x1.2296ABFB0FB02p-1),
			random: samplerZRandomBytes(t,
				"EB7B3225E4DD31ED36", "88", "05",
			),
			want: -13,
		},
		{
			name:   "sample-13",
			mu:     fpr(0x1.C87E35E3D3FC4p+4),
			isigma: fpr(0x1.2296ABFB0FB02p-1),
			random: samplerZRandomBytes(t,
				"0B4E68B248A677835C", "88", "ba",
				"B2E8DCA849C5D1B8FD", "8a", "2e",
			),
			want: 28,
		},
		{
			name:   "sample-14",
			mu:     fpr(0x1.D23EDCECDB37Bp+5),
			isigma: fpr(0x1.22D81A75F8BC3p-1),
			random: samplerZRandomBytes(t,
				"72EC586CAD2529DAF2", "75", "6d",
			),
			want: 60,
		},
		{
			name:   "sample-15",
			mu:     fpr(-0x1.1078846D50001p+3),
			isigma: fpr(0x1.22D81A75F8BC3p-1),
			random: samplerZRandomBytes(t,
				"CEF87D5D741AB8BEBE", "7f", "a6",
			),
			want: -8,
		},
		{
			name:   "sample-16",
			mu:     fpr(-0x1.91902959F8241p+2),
			isigma: fpr(0x1.2230BAA911BBDp-1),
			random: samplerZRandomBytes(t,
				"1436ED556F5128268C", "11", "04",
			),
			want: -3,
		},
		{
			name:   "sample-17",
			mu:     fpr(0x1.2E52380A11663p+4),
			isigma: fpr(0x1.2230BAA911BBDp-1),
			random: samplerZRandomBytes(t,
				"3B42C7289305C2B83F", "4a", "38",
			),
			want: 16,
		},
		{
			name:   "sample-18",
			mu:     fpr(0x1.6FD5988552264p+1),
			isigma: fpr(0x1.226706D32BB75p-1),
			random: samplerZRandomBytes(t,
				"FD60C84C5BD9DB6738", "42", "78",
			),
			want: 2,
		},
		{
			name:   "sample-19",
			mu:     fpr(0x1.D2FE502BA977Fp+5),
			isigma: fpr(0x1.226706D32BB75p-1),
			random: samplerZRandomBytes(t,
				"2D4E0366F86DB94E54", "71", "15",
			),
			want: 61,
		},
		{
			name:   "sample-20",
			mu:     fpr(0x1.02BED22716525p+3),
			isigma: fpr(0x1.2277962FA5C9Ap-1),
			random: samplerZRandomBytes(t,
				"9FFA24F76C3EB32DF1", "71", "3a",
			),
			want: 10,
		},
		{
			name:   "sample-21",
			mu:     fpr(-0x1.1666CC79409E3p+5),
			isigma: fpr(0x1.2277962FA5C9Ap-1),
			random: samplerZRandomBytes(t,
				"3A4EBE02A22A9D8F77", "ed", "2e",
			),
			want: -32,
		},
		{
			name:   "sample-22",
			mu:     fpr(-0x1.428884353F5ACp+4),
			isigma: fpr(0x1.22B08DD8705DEp-1),
			random: samplerZRandomBytes(t,
				"CE6C1980786FC620F3", "dc", "92",
			),
			want: -21,
		},
		{
			name:   "sample-23",
			mu:     fpr(-0x1.2B6D48C3253F6p+6),
			isigma: fpr(0x1.22B08DD8705DEp-1),
			random: samplerZRandomBytes(t,
				"D509A94B8157F8F728", "a1", "00",
			),
			want: -74,
		},
		{
			name:   "sample-24",
			mu:     fpr(0x1.03849092005CEp+4),
			isigma: fpr(0x1.22CD5D9050D8Ap-1),
			random: samplerZRandomBytes(t,
				"A71615FED56C8D4BBF", "8d", "a0",
			),
			want: 17,
		},
		{
			name:   "sample-25",
			mu:     fpr(-0x1.ADD49FE03DBFEp+1),
			isigma: fpr(0x1.22CD5D9050D8Ap-1),
			random: samplerZRandomBytes(t,
				"72E6441C8C58CE1E20", "b3", "a0",
			),
			want: -2,
		},
		{
			name:   "sample-26",
			mu:     fpr(0x1.9F012402CC4E8p+4),
			isigma: fpr(0x1.230B71A547B0Dp-1),
			random: samplerZRandomBytes(t,
				"02B58D0D9429B5ACAC", "13", "fa",
				"9795FA963022748EFB", "7a", "aa",
				"422C6D4897F8B5050B", "a2", "21",
			),
			want: 23,
		},
		{
			name:   "sample-27",
			mu:     fpr(-0x1.33F0976FE6F1Cp+6),
			isigma: fpr(0x1.230B71A547B0Dp-1),
			random: samplerZRandomBytes(t,
				"64D705DA002DE9A15A", "2c", "46",
			),
			want: -78,
		},
		{
			name:   "sample-28",
			mu:     fpr(0x1.89C3EC312F6BDp+3),
			isigma: fpr(0x1.232375667BE2Cp-1),
			random: samplerZRandomBytes(t,
				"A49C0B3B44A2EDB49F", "b4", "c6",
				"4BDBE27BB0FA2F2DF6", "b0", "33",
			),
			want: 10,
		},
		{
			name:   "sample-29",
			mu:     fpr(0x1.56F2DCE644F6Dp+3),
			isigma: fpr(0x1.232375667BE2Cp-1),
			random: samplerZRandomBytes(t,
				"CED5EC97678A6E57D1", "9b", "53",
			),
			want: 11,
		},
		{
			name:   "sample-30",
			mu:     fpr(0x1.432DFB2A8F7DAp+6),
			isigma: fpr(0x1.2365B211DF050p-1),
			random: samplerZRandomBytes(t,
				"A8E6A8958B7C7C59CD", "4a", "d7",
				"2B01D558170098471F", "4a", "4d",
			),
			want: 78,
		},
		{
			name:   "sample-31",
			mu:     fpr(-0x1.EF9969C11D364p+4),
			isigma: fpr(0x1.2365B211DF050p-1),
			random: samplerZRandomBytes(t,
				"121A132D840FC5B7BC", "b8", "f1",
				"767206F7D33975129A", "f9", "99",
				"66F69BFEBDB5311B1F", "3c", "5b",
			),
			want: -32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prng := newSamplerPRNGFromBytes(tc.random)
			if got := sampleFFTPoint(prng, tc.mu, tc.isigma); got != tc.want {
				t.Fatalf("sampleFFTPoint = %v, want %v", got, tc.want)
			}
		})
	}
}

func newSamplerPRNGFromBytes(b []byte) *samplerPRNG {
	var p samplerPRNG
	copy(p.buf[:], b)
	return &p
}

func samplerZRandomBytes(t *testing.T, parts ...string) []byte {
	t.Helper()

	var out []byte
	for _, part := range parts {
		b := mustDecodeHex(t, part)
		if len(b) == 9 {
			for i := len(b) - 1; i >= 0; i-- {
				out = append(out, b[i])
			}
			continue
		}
		out = append(out, b...)
	}
	return out
}
