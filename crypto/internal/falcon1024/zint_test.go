package falcon1024

import (
	"slices"
	"testing"
)

// These zint vectors were generated from throwaway C harnesses that include
// the Falcon reference implementation. They are reference-derived generated
// intermediates, not published Falcon KATs.
// Source: https://falcon-sign.info/impl/keygen.c.html

func TestZintSub(t *testing.T) {
	for _, tc := range []struct {
		name      string
		a         []uint32
		b         []uint32
		ctl       uint32
		want      []uint32
		wantCarry uint32
	}{
		{
			name:      "no borrow",
			a:         []uint32{123456789, 42, 17},
			b:         []uint32{123456788, 40, 1},
			ctl:       1,
			want:      []uint32{1, 2, 16},
			wantCarry: 0,
		},
		{
			name:      "borrow chain",
			a:         []uint32{0, 0, 1},
			b:         []uint32{1, 0, 0},
			ctl:       1,
			want:      []uint32{2147483647, 2147483647, 0},
			wantCarry: 0,
		},
		{
			name:      "disabled",
			a:         []uint32{7, 8, 9},
			b:         []uint32{9, 8, 7},
			ctl:       0,
			want:      []uint32{7, 8, 9},
			wantCarry: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := slices.Clone(tc.a)
			if gotCarry := zintSub(a, tc.b, tc.ctl); gotCarry != tc.wantCarry {
				t.Fatalf("zintSub carry = %d, want %d", gotCarry, tc.wantCarry)
			}
			requireEqualWords(t, "zintSub", a, tc.want)
		})
	}
}

func TestZintMulSmall(t *testing.T) {
	for _, tc := range []struct {
		name      string
		m         []uint32
		x         uint32
		want      []uint32
		wantCarry uint32
	}{
		{
			name:      "small",
			m:         []uint32{1, 2, 3},
			x:         12289,
			want:      []uint32{12289, 24578, 36867},
			wantCarry: 0,
		},
		{
			name:      "carry",
			m:         []uint32{2147483647, 2147483646, 123456789},
			x:         12289,
			want:      []uint32{2147471359, 2147471358, 1037036821},
			wantCarry: 706,
		},
		{
			name:      "large multiplier",
			m:         []uint32{318507837, 1006190406, 445522722, 516055551},
			x:         2147473409,
			want:      []uint32{825918269, 1561482388, 554303402, 1509991637},
			wantCarry: 516053090,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := slices.Clone(tc.m)
			if gotCarry := zintMulSmall(m, tc.x); gotCarry != tc.wantCarry {
				t.Fatalf("zintMulSmall carry = %d, want %d", gotCarry, tc.wantCarry)
			}
			requireEqualWords(t, "zintMulSmall", m, tc.want)
		})
	}
}

func TestZintModSmallUnsigned(t *testing.T) {
	for _, tc := range []struct {
		name       string
		d          []uint32
		primeIndex int
		want       uint32
	}{
		{
			name:       "small prime 0",
			d:          []uint32{1, 2, 3},
			primeIndex: 0,
			want:       314531842,
		},
		{
			name:       "small prime 209",
			d:          []uint32{1, 2, 3},
			primeIndex: 209,
			want:       1241937051,
		},
		{
			name:       "mixed prime 0",
			d:          []uint32{2147483647, 2147483646, 123456789, 987654321},
			primeIndex: 0,
			want:       95393309,
		},
		{
			name:       "mixed prime 216",
			d:          []uint32{2147483647, 2147483646, 123456789, 987654321},
			primeIndex: 216,
			want:       1336452365,
		},
		{
			name:       "reference prime 209",
			d:          []uint32{318507837, 1006190406, 445522722, 516055551},
			primeIndex: 209,
			want:       1677852819,
		},
		{
			name:       "reference prime 210",
			d:          []uint32{318507837, 1006190406, 445522722, 516055551},
			primeIndex: 210,
			want:       1733543662,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, p0i, r2 := zintPrimeParams(tc.primeIndex)
			if got := zintModSmallUnsigned(tc.d, p, p0i, r2); got != tc.want {
				t.Fatalf("zintModSmallUnsigned = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestZintModSmallSigned(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		p, p0i, r2 := zintPrimeParams(0)
		if got := zintModSmallSigned(nil, p, p0i, r2, 0); got != 0 {
			t.Fatalf("zintModSmallSigned = %d, want 0", got)
		}
	})

	for _, tc := range []struct {
		name       string
		d          []uint32
		primeIndex int
		want       uint32
	}{
		{
			name:       "positive",
			d:          []uint32{1, 2, 3},
			primeIndex: 0,
			want:       314531842,
		},
		{
			name:       "negative prime 0",
			d:          []uint32{2147483643, 2147483647, 1073741824},
			primeIndex: 0,
			want:       1333285111,
		},
		{
			name:       "negative prime 216",
			d:          []uint32{2147483643, 2147483647, 1073741824},
			primeIndex: 216,
			want:       475258429,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, p0i, r2 := zintPrimeParams(tc.primeIndex)
			rx := modPRx(len(tc.d), p, p0i, r2)
			if got := zintModSmallSigned(tc.d, p, p0i, r2, rx); got != tc.want {
				t.Fatalf("zintModSmallSigned = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestZintAddMulSmall(t *testing.T) {
	for _, tc := range []struct {
		name string
		x    []uint32
		y    []uint32
		s    uint32
		want []uint32
	}{
		{
			name: "small",
			x:    []uint32{5, 6, 7, 0},
			y:    []uint32{11, 12, 13},
			s:    12289,
			want: []uint32{135184, 147474, 159764, 0},
		},
		{
			name: "carry",
			x:    []uint32{2147483640, 2147483630, 42, 0},
			y:    []uint32{2147483647, 123456789, 987654321},
			s:    2147473409,
			want: []uint32{10231, 793795844, 31361957, 987649612},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := slices.Clone(tc.x)
			zintAddMulSmall(x, tc.y, tc.s)
			requireEqualWords(t, "zintAddMulSmall", x, tc.want)
		})
	}
}

func TestZintNormZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		x    []uint32
		p    []uint32
		want []uint32
	}{
		{
			name: "below half",
			x:    []uint32{40, 0, 0},
			p:    []uint32{101, 0, 0},
			want: []uint32{40, 0, 0},
		},
		{
			name: "above half",
			x:    []uint32{60, 0, 0},
			p:    []uint32{101, 0, 0},
			want: []uint32{2147483607, 2147483647, 2147483647},
		},
		{
			name: "wide",
			x:    []uint32{2147483646, 2147483646, 10},
			p:    []uint32{2147483647, 2147483646, 17},
			want: []uint32{2147483647, 2147483647, 2147483640},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := slices.Clone(tc.x)
			zintNormZero(x, tc.p)
			requireEqualWords(t, "zintNormZero", x, tc.want)
		})
	}
}

func TestZintRebuildCRT(t *testing.T) {
	for _, tc := range []struct {
		name            string
		xx              []uint32
		count           int
		normalizeSigned bool
		want            []uint32
	}{
		{
			name:            "unsigned",
			xx:              []uint32{1, 2, 3, 123, 456, 789},
			count:           2,
			normalizeSigned: false,
			want:            []uint32{116849192, 1180448205, 612339150, 1776501976, 1643101678, 2064339632},
		},
		{
			name:            "signed",
			xx:              []uint32{1, 2, 3, 123, 456, 789},
			count:           2,
			normalizeSigned: true,
			want:            []uint32{116849192, 1180448205, 612339150, 1495684311, 1362527950, 2064540328},
		},
		{
			// Replicates the count=2 unsigned data four times; since each of
			// the count entries is rebuilt independently, the expected output
			// is the unsigned-case want concatenated four times. This exercises
			// the outer batching loop with count > 2.
			name: "unsigned count=8",
			xx: []uint32{
				1, 2, 3, 123, 456, 789,
				1, 2, 3, 123, 456, 789,
				1, 2, 3, 123, 456, 789,
				1, 2, 3, 123, 456, 789,
			},
			count:           8,
			normalizeSigned: false,
			want: []uint32{
				116849192, 1180448205, 612339150, 1776501976, 1643101678, 2064339632,
				116849192, 1180448205, 612339150, 1776501976, 1643101678, 2064339632,
				116849192, 1180448205, 612339150, 1776501976, 1643101678, 2064339632,
				116849192, 1180448205, 612339150, 1776501976, 1643101678, 2064339632,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xx := slices.Clone(tc.xx)
			zintRebuildCRT(xx, 3, 3, tc.count, smallPrimes[:], tc.normalizeSigned, make([]uint32, 3))
			requireEqualWords(t, "zintRebuildCRT", xx, tc.want)
		})
	}
}

func TestZintNegate(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    []uint32
		ctl  uint32
		want []uint32
	}{
		{
			name: "enabled",
			a:    []uint32{5, 0, 0},
			ctl:  1,
			want: []uint32{2147483643, 2147483647, 2147483647},
		},
		{
			name: "disabled",
			a:    []uint32{5, 0, 0},
			ctl:  0,
			want: []uint32{5, 0, 0},
		},
		{
			name: "carry",
			a:    []uint32{2147483647, 2147483647, 0},
			ctl:  1,
			want: []uint32{1, 0, 2147483647},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := slices.Clone(tc.a)
			zintNegate(a, tc.ctl)
			requireEqualWords(t, "zintNegate", a, tc.want)
		})
	}
}

func TestZintCoReduce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a     []uint32
		b     []uint32
		xa    int64
		xb    int64
		ya    int64
		yb    int64
		want  uint32
		wantA []uint32
		wantB []uint32
	}{
		{
			name:  "positive",
			a:     []uint32{100, 200, 300},
			b:     []uint32{400, 500, 600},
			xa:    2147483648,
			xb:    0,
			ya:    0,
			yb:    2147483648,
			want:  0,
			wantA: []uint32{100, 200, 300},
			wantB: []uint32{400, 500, 600},
		},
		{
			name:  "mixed",
			a:     []uint32{100, 200, 300},
			b:     []uint32{400, 500, 600},
			xa:    -2147483648,
			xb:    0,
			ya:    0,
			yb:    2147483648,
			want:  1,
			wantA: []uint32{100, 200, 300},
			wantB: []uint32{400, 500, 600},
		},
		{
			name:  "linear",
			a:     []uint32{100, 200, 300},
			b:     []uint32{400, 500, 600},
			xa:    2147483648,
			xb:    2147483648,
			ya:    -2147483648,
			yb:    2147483648,
			want:  0,
			wantA: []uint32{500, 700, 900},
			wantB: []uint32{300, 300, 300},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := slices.Clone(tc.a)
			b := slices.Clone(tc.b)
			if got := zintCoReduce(a, b, tc.xa, tc.xb, tc.ya, tc.yb); got != tc.want {
				t.Fatalf("zintCoReduce = %d, want %d", got, tc.want)
			}
			requireEqualWords(t, "zintCoReduce a", a, tc.wantA)
			requireEqualWords(t, "zintCoReduce b", b, tc.wantB)
		})
	}
}

func TestZintFinishMod(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    []uint32
		m    []uint32
		neg  uint32
		want []uint32
	}{
		{
			name: "below",
			a:    []uint32{50, 0, 0},
			m:    []uint32{101, 0, 0},
			neg:  0,
			want: []uint32{50, 0, 0},
		},
		{
			name: "above",
			a:    []uint32{150, 0, 0},
			m:    []uint32{101, 0, 0},
			neg:  0,
			want: []uint32{49, 0, 0},
		},
		{
			name: "negative",
			a:    []uint32{2147483643, 2147483647, 2147483647},
			m:    []uint32{101, 0, 0},
			neg:  1,
			want: []uint32{96, 0, 0},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := slices.Clone(tc.a)
			zintFinishMod(a, tc.m, tc.neg)
			requireEqualWords(t, "zintFinishMod", a, tc.want)
		})
	}
}

func TestZintCoReduceMod(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a     []uint32
		b     []uint32
		m     []uint32
		xa    int64
		xb    int64
		ya    int64
		yb    int64
		wantA []uint32
		wantB []uint32
	}{
		{
			name:  "identity",
			a:     []uint32{5, 0, 0},
			b:     []uint32{7, 0, 0},
			m:     []uint32{101, 0, 0},
			xa:    2147483648,
			xb:    0,
			ya:    0,
			yb:    2147483648,
			wantA: []uint32{5, 0, 0},
			wantB: []uint32{7, 0, 0},
		},
		{
			name:  "linear",
			a:     []uint32{5, 0, 0},
			b:     []uint32{7, 0, 0},
			m:     []uint32{101, 0, 0},
			xa:    2147483648,
			xb:    2147483648,
			ya:    -2147483648,
			yb:    2147483648,
			wantA: []uint32{12, 0, 0},
			wantB: []uint32{2, 0, 0},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := slices.Clone(tc.a)
			b := slices.Clone(tc.b)
			m0i := modPNInv31(tc.m[0])
			zintCoReduceMod(a, b, tc.m, m0i, tc.xa, tc.xb, tc.ya, tc.yb)
			requireEqualWords(t, "zintCoReduceMod a", a, tc.wantA)
			requireEqualWords(t, "zintCoReduceMod b", b, tc.wantB)
		})
	}
}

func TestZintBezout(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if zintBezout(nil, nil, nil, nil, nil) {
			t.Fatal("zintBezout returned true for empty inputs")
		}
	})

	for _, tc := range []struct {
		name  string
		x     []uint32
		y     []uint32
		want  bool
		wantU []uint32
		wantV []uint32
	}{
		{
			name:  "coprime",
			x:     []uint32{3, 0},
			y:     []uint32{5, 0},
			want:  true,
			wantU: []uint32{2, 0},
			wantV: []uint32{1, 0},
		},
		{
			name:  "not coprime",
			x:     []uint32{9, 0},
			y:     []uint32{15, 0},
			want:  false,
			wantU: []uint32{12, 0},
			wantV: []uint32{7, 0},
		},
		{
			name:  "wide",
			x:     []uint32{2147483647, 1},
			y:     []uint32{2147483629, 2},
			want:  false,
			wantU: []uint32{674923418, 2},
			wantV: []uint32{1165776837, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := make([]uint32, len(tc.x))
			v := make([]uint32, len(tc.x))
			tmp := make([]uint32, 4*len(tc.x))
			if got := zintBezout(u, v, tc.x, tc.y, tmp); got != tc.want {
				t.Fatalf("zintBezout = %t, want %t", got, tc.want)
			}
			requireEqualWords(t, "zintBezout u", u, tc.wantU)
			requireEqualWords(t, "zintBezout v", v, tc.wantV)
		})
	}
}

func TestZintAddScaledMulSmall(t *testing.T) {
	t.Run("empty y", func(t *testing.T) {
		x := []uint32{1, 2, 3}
		want := slices.Clone(x)
		zintAddScaledMulSmall(x, nil, 11, 1, 3)
		requireEqualWords(t, "zintAddScaledMulSmall", x, want)
	})

	for _, tc := range []struct {
		name string
		x    []uint32
		y    []uint32
		k    int32
		sch  uint32
		scl  uint32
		want []uint32
	}{
		{
			name: "positive",
			x:    []uint32{1, 2, 3, 4, 5},
			y:    []uint32{7, 8, 9},
			k:    11,
			sch:  1,
			scl:  3,
			want: []uint32{1, 618, 707, 796, 5},
		},
		{
			name: "negative k",
			x:    []uint32{1, 2, 3, 4, 5},
			y:    []uint32{7, 8, 9},
			k:    -11,
			sch:  0,
			scl:  5,
			want: []uint32{2147481185, 2147480833, 2147480482, 3, 5},
		},
		{
			name: "negative y",
			x:    []uint32{1, 2, 3, 4, 5},
			y:    []uint32{7, 8, 1073741824},
			k:    11,
			sch:  1,
			scl:  3,
			want: []uint32{1, 618, 707, 4, 2147483609},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := slices.Clone(tc.x)
			zintAddScaledMulSmall(x, tc.y, tc.k, tc.sch, tc.scl)
			requireEqualWords(t, "zintAddScaledMulSmall", x, tc.want)
		})
	}
}

func TestZintSubScaled(t *testing.T) {
	t.Run("empty y", func(t *testing.T) {
		x := []uint32{1, 2, 3}
		want := slices.Clone(x)
		zintSubScaled(x, nil, 1, 3)
		requireEqualWords(t, "zintSubScaled", x, want)
	})

	for _, tc := range []struct {
		name string
		x    []uint32
		y    []uint32
		sch  uint32
		scl  uint32
		want []uint32
	}{
		{
			name: "positive",
			x:    []uint32{1, 2, 3, 4, 5},
			y:    []uint32{7, 8, 9},
			sch:  1,
			scl:  3,
			want: []uint32{1, 2147483594, 2147483586, 2147483579, 4},
		},
		{
			name: "negative y",
			x:    []uint32{1, 2, 3, 4, 5},
			y:    []uint32{7, 8, 1073741824},
			sch:  1,
			scl:  3,
			want: []uint32{1, 2147483594, 2147483586, 3, 9},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := slices.Clone(tc.x)
			zintSubScaled(x, tc.y, tc.sch, tc.scl)
			requireEqualWords(t, "zintSubScaled", x, tc.want)
		})
	}
}

func TestZintOneToPlain(t *testing.T) {
	for _, tc := range []struct {
		name string
		x    uint32
		want int32
	}{
		{name: "zero", x: 0, want: 0},
		{name: "positive", x: 123456789, want: 123456789},
		{name: "max positive", x: 1073741823, want: 1073741823},
		{name: "negative one", x: 2147483647, want: -1},
		{name: "min negative", x: 1073741824, want: -1073741824},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := zintOneToPlain(tc.x); got != tc.want {
				t.Fatalf("zintOneToPlain = %d, want %d", got, tc.want)
			}
		})
	}
}

func zintPrimeParams(primeIndex int) (p, p0i, r2 uint32) {
	p = smallPrimes[primeIndex].p
	p0i = smallPrimeDerivedValues[primeIndex].p0i
	r2 = smallPrimeDerivedValues[primeIndex].r2
	return p, p0i, r2
}
