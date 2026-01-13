package params

import "testing"

// TestParamsInit verifies that the package initializes correctly.
// The init() function contains compile-time assertions that panic if invalid.
// This test implicitly verifies those assertions pass.
func TestParamsInit(t *testing.T) {
	// If we reach here, init() didn't panic - constants are valid
	if SPX_N != 32 {
		t.Errorf("SPX_N = %d, want 32", SPX_N)
	}
	if SPX_WOTS_W != 16 {
		t.Errorf("SPX_WOTS_W = %d, want 16", SPX_WOTS_W)
	}
	if SPX_TREE_HEIGHT*SPX_D != SPX_FULL_HEIGHT {
		t.Errorf("SPX_TREE_HEIGHT * SPX_D = %d, want %d", SPX_TREE_HEIGHT*SPX_D, SPX_FULL_HEIGHT)
	}
}

// TestValidateParams_Valid tests that valid parameters pass validation.
func TestValidateParams_Valid(t *testing.T) {
	err := ValidateParams(16, 32, 8, 8, 64)
	if err != nil {
		t.Errorf("ValidateParams with valid params returned error: %v", err)
	}
}

// TestValidateParams_InvalidWotsW tests that invalid WOTS_W is rejected.
func TestValidateParams_InvalidWotsW(t *testing.T) {
	err := ValidateParams(8, 32, 8, 8, 64) // wotsW != 16
	if err == nil {
		t.Error("expected error for invalid WOTS_W")
	}
	pe, ok := err.(*ParamError)
	if !ok {
		t.Fatalf("expected *ParamError, got %T", err)
	}
	if pe.Param != "SPX_WOTS_W" {
		t.Errorf("expected param SPX_WOTS_W, got %s", pe.Param)
	}
}

// TestValidateParams_InvalidN tests that invalid N is rejected.
func TestValidateParams_InvalidN(t *testing.T) {
	err := ValidateParams(16, 64, 8, 8, 64) // n != 32
	if err == nil {
		t.Error("expected error for invalid N")
	}
	pe, ok := err.(*ParamError)
	if !ok {
		t.Fatalf("expected *ParamError, got %T", err)
	}
	if pe.Param != "SPX_N" {
		t.Errorf("expected param SPX_N, got %s", pe.Param)
	}
}

// TestValidateParams_InvalidTreeHeight tests that invalid tree height is rejected.
func TestValidateParams_InvalidTreeHeight(t *testing.T) {
	err := ValidateParams(16, 32, 4, 8, 64) // treeHeight*d != fullHeight (4*8=32 != 64)
	if err == nil {
		t.Error("expected error for invalid tree height")
	}
	pe, ok := err.(*ParamError)
	if !ok {
		t.Fatalf("expected *ParamError, got %T", err)
	}
	if pe.Param != "SPX_TREE_HEIGHT*SPX_D" {
		t.Errorf("expected param SPX_TREE_HEIGHT*SPX_D, got %s", pe.Param)
	}
}

// TestParamError_Error tests the ParamError.Error() method.
func TestParamError_Error(t *testing.T) {
	pe := &ParamError{Param: "TEST", Got: 5, Expected: 10}
	errStr := pe.Error()
	if errStr == "" {
		t.Error("Error() returned empty string")
	}
}

// TestParamsDerived verifies derived constants are calculated correctly.
func TestParamsDerived(t *testing.T) {
	// Verify WOTS length calculations
	expectedLen1 := 8 * SPX_N / SPX_WOTS_LOGW
	if SPX_WOTS_LEN1 != expectedLen1 {
		t.Errorf("SPX_WOTS_LEN1 = %d, want %d", SPX_WOTS_LEN1, expectedLen1)
	}

	if SPX_WOTS_LEN != SPX_WOTS_LEN1+SPX_WOTS_LEN2 {
		t.Errorf("SPX_WOTS_LEN = %d, want %d", SPX_WOTS_LEN, SPX_WOTS_LEN1+SPX_WOTS_LEN2)
	}

	// Verify key sizes
	if SPX_PK_BYTES != 2*SPX_N {
		t.Errorf("SPX_PK_BYTES = %d, want %d", SPX_PK_BYTES, 2*SPX_N)
	}

	if SPX_SK_BYTES != 2*SPX_N+SPX_PK_BYTES {
		t.Errorf("SPX_SK_BYTES = %d, want %d", SPX_SK_BYTES, 2*SPX_N+SPX_PK_BYTES)
	}
}

// TestParamsOffsets verifies SHAKE address offsets.
func TestParamsOffsets(t *testing.T) {
	if SPX_SHAKE != 1 {
		t.Errorf("SPX_SHAKE = %d, want 1", SPX_SHAKE)
	}

	// Verify offsets are within address bounds
	if SPX_OFFSET_TREE_INDEX >= SPX_ADDR_BYTES {
		t.Errorf("SPX_OFFSET_TREE_INDEX = %d exceeds SPX_ADDR_BYTES = %d", SPX_OFFSET_TREE_INDEX, SPX_ADDR_BYTES)
	}
}
