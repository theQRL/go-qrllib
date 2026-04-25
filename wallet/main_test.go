package wallet

import (
	"os"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/sphincsplus_256s"
)

// TestMain enables the SPHINCS+ wallet path for the duration of this
// package's test binary so cross-algorithm tests can exercise both
// ML-DSA-87 and SPHINCS+ wallets. SPHINCSPLUS_256S is a forward
// placeholder for SLH-DSA (FIPS 205) and is gated off in production
// (see wallet/sphincsplus_256s/doc.go).
func TestMain(m *testing.M) {
	prev := sphincsplus_256s.EnableExperimentalForTesting(true)
	code := m.Run()
	sphincsplus_256s.EnableExperimentalForTesting(prev)
	os.Exit(code)
}
