package falcon1024

import (
	"math"
	"testing"
)

func TestFPRRint(t *testing.T) {
	// Falcon fpr_rint rounds to nearest integer with ties to even.
	testCases := []struct {
		x    fpr
		want int64
	}{
		{x: -3.75, want: -4},
		{x: -2.5, want: -2},
		{x: -1.5, want: -2},
		{x: -0.5, want: 0},
		{x: 0.5, want: 0},
		{x: 1.5, want: 2},
		{x: 2.5, want: 2},
		{x: 3.75, want: 4},
	}

	for _, tc := range testCases {
		if got := fprRint(tc.x); got != tc.want {
			t.Fatalf("fprRint(%v) = %d, want %d", tc.x, got, tc.want)
		}
	}
}

func TestFPRTrunc(t *testing.T) {
	testCases := []struct {
		x    fpr
		want int64
	}{
		{x: -3.75, want: -3},
		{x: -0.5, want: 0},
		{x: 0, want: 0},
		{x: 0.5, want: 0},
		{x: 3.75, want: 3},
	}

	for _, tc := range testCases {
		if got := fprTrunc(tc.x); got != tc.want {
			t.Fatalf("fprTrunc(%v) = %d, want %d", tc.x, got, tc.want)
		}
	}
}

func TestFPRExpmP63(t *testing.T) {
	// Compare against the native Horner polynomial from the Falcon reference
	// fpr_expm_p63 helper. The production helper uses the fixed-point form.
	testCases := []struct {
		x   fpr
		ccs fpr
	}{
		{x: 0, ccs: 0.5},
		{x: log2 * 0.125, ccs: 0.625},
		{x: log2 * 0.25, ccs: 0.75},
		{x: log2 * 0.5, ccs: 0.875},
		{x: log2 * 0.875, ccs: 0.5},
	}

	for _, tc := range testCases {
		got := fprExpmP63(tc.x, tc.ccs)
		want := fprExpmP63Reference(tc.x, tc.ccs)
		if d := uint64AbsDiff(got, want); d > 1<<12 {
			t.Fatalf("fprExpmP63(%v, %v) = %d, want about %d (diff %d)", tc.x, tc.ccs, got, want, d)
		}
	}
}

func fprExpmP63Reference(x, ccs fpr) uint64 {
	d := float64(x)
	y := 0.000000002073772366009083061987
	y = 0.000000025299506379442070029551 - y*d
	y = 0.000000275607356160477811864927 - y*d
	y = 0.000002755586350219122514855659 - y*d
	y = 0.000024801566833585381209939524 - y*d
	y = 0.000198412739277311890541063977 - y*d
	y = 0.001388888894063186997887560103 - y*d
	y = 0.008333333327800835146903501993 - y*d
	y = 0.041666666666110491190622155955 - y*d
	y = 0.166666666666984014666397229121 - y*d
	y = 0.500000000000019206858326015208 - y*d
	y = 0.999999999999994892974086724280 - y*d
	y = 1.000000000000000000000000000000 - y*d
	y *= float64(ccs)
	return uint64(y * math.Ldexp(1, 63))
}

func uint64AbsDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
