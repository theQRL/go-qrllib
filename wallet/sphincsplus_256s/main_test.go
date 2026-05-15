package sphincsplus_256s

import (
	"os"
	"testing"
)

// TestMain enables the experimental flag for the duration of the test
// binary so the existing wallet test suite continues to exercise the
// SPHINCS+ implementation. Production callers do not see this — the
// flag is package-internal and defaults to false.
//
// Tests that need to assert the gate's behaviour (i.e. that public
// constructors refuse and Verify returns false when SPHINCSPLUS_256S
// is not issuable / verifiable) must explicitly flip the flag off via
// EnableExperimentalForTesting(false) and restore it on cleanup.
func TestMain(m *testing.M) {
	prev := EnableExperimentalForTesting(true)
	code := m.Run()
	EnableExperimentalForTesting(prev)
	os.Exit(code)
}
