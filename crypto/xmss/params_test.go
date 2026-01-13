package xmss

import (
	"fmt"
	"testing"
)

func TestNewWOTSParams_ValidW(t *testing.T) {
	// Valid w values: 4 (logW=2), 16 (logW=4), 256 (logW=8)
	tests := []struct {
		name string
		w    uint32
		logW uint32
	}{
		{"w=4 (logW=2)", 4, 2},
		{"w=16 (logW=4)", 16, 4},
		{"w=256 (logW=8)", 256, 8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := NewWOTSParams(WOTSParamN, tc.w)
			if params.logW != tc.logW {
				t.Errorf("NewWOTSParams(32, %d).logW = %d, want %d", tc.w, params.logW, tc.logW)
			}
			if params.w != tc.w {
				t.Errorf("NewWOTSParams(32, %d).w = %d, want %d", tc.w, params.w, tc.w)
			}
		})
	}
}

func TestNewWOTSParams_InvalidW_Panics(t *testing.T) {
	// Invalid w values that produce logW != 2, 4, or 8 after truncation
	// logW = uint32(math.Log2(float64(w)))
	tests := []struct {
		w    uint32
		logW uint32 // expected truncated value
	}{
		{1, 0},   // log2(1)=0
		{2, 1},   // log2(2)=1
		{3, 1},   // log2(3)≈1.58 -> 1
		{8, 3},   // log2(8)=3
		{32, 5},  // log2(32)=5
		{64, 6},  // log2(64)=6
		{128, 7}, // log2(128)=7
	}

	for _, tc := range tests {
		t.Run("w="+fmt.Sprint(tc.w), func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("NewWOTSParams(32, %d) with logW=%d did not panic", tc.w, tc.logW)
				}
			}()
			NewWOTSParams(WOTSParamN, tc.w)
		})
	}
}

func TestNewXMSSParams(t *testing.T) {
	params := NewXMSSParams(WOTSParamN, 10, WOTSParamW, WOTSParamK)

	if params.n != WOTSParamN {
		t.Errorf("n = %d, want %d", params.n, WOTSParamN)
	}
	if params.h != 10 {
		t.Errorf("h = %d, want 10", params.h)
	}
	if params.k != WOTSParamK {
		t.Errorf("k = %d, want %d", params.k, WOTSParamK)
	}
	if params.wotsParams == nil {
		t.Error("wotsParams is nil")
	}
}
