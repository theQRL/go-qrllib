// Security regression test for finding H1 (wallet variant): a public key
// whose t1 region is all zero is universally forgeable.
//
// The wallet Verify path forwards to crypto/ml_dsa_87.Verify after
// binding the descriptor-derived signing context. A forger who sets
// z = 0, h = 0 and c~ = SHAKE256(mu || w1Encode(0)) produces a signature
// that a t1 = 0 key accepts, using only public data. See the core-level
// test (crypto/ml_dsa_87/zero_t1_forgery_test.go) for the full rationale.
//
// SECURE EXPECTATION: wallet Verify MUST reject a public key whose t1
// region (bytes mldsa.SEED_BYTES..PKSize) is all zero. This assertion
// FAILS against the current unpatched code (demonstrating the forgery)
// and PASSES once the guard lands.

package ml_dsa_87

import (
	"crypto/sha3"
	"fmt"
	"testing"

	mldsa "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

// forgeZeroT1WalletSig builds the raw forged signature bytes for a t1 = 0
// public key and the given wallet signing context, using only public
// inputs. It mirrors forgeZeroT1Sig at the core layer but emits raw bytes
// (the wallet Verify takes a []uint8 signature).
func forgeZeroT1WalletSig(pk []byte, ctx, msg []byte) []byte {
	pre := make([]byte, len(ctx)+2)
	pre[0] = 0
	pre[1] = byte(len(ctx))
	copy(pre[2:], ctx)

	tr := sha3.SumSHAKE256(pk, mldsa.TR_BYTES)

	mu := make([]byte, mldsa.CRH_BYTES)
	st := sha3.NewSHAKE256()
	_, _ = st.Write(tr)
	_, _ = st.Write(pre)
	_, _ = st.Write(msg)
	_, _ = st.Read(mu)

	w1enc := make([]byte, mldsa.K*mldsa.POLY_W1_PACKED_BYTES) // all zero
	cTilde := make([]byte, mldsa.C_TILDE_BYTES)
	st.Reset()
	_, _ = st.Write(mu)
	_, _ = st.Write(w1enc)
	_, _ = st.Read(cTilde)

	// sig = c~ || (z = 0 packed) * L || (h = 0 encoding: OMEGA+K zero bytes).
	// polyZPack of an all-zero polynomial is the repeating 5-byte group
	// {0x00,0x00,0x08,0x00,0x80} (t = GAMMA1 - 0 = 0x80000).
	sig := make([]byte, 0, mldsa.CRYPTO_BYTES)
	sig = append(sig, cTilde...)
	for i := 0; i < mldsa.L; i++ {
		for j := 0; j+5 <= mldsa.POLY_Z_PACKED_BYTES; j += 5 {
			sig = append(sig, 0x00, 0x00, 0x08, 0x00, 0x80)
		}
	}
	sig = append(sig, make([]byte, mldsa.OMEGA+mldsa.K)...)
	return sig
}

// walletSigningContext returns the context the wallet Verify path binds
// for the given descriptor, so the forgery hashes the same mu.
func walletSigningContext(desc descriptor.Descriptor) []byte {
	return common.SigningContext(desc)
}

// zeroT1AddrStr returns the canonical "Q%x" address that pk maps to under
// descriptor d (matching Wallet.GetAddressStr), for inclusion in failure
// logs. It fails the test if the address cannot be derived.
func zeroT1AddrStr(t *testing.T, pk PK, d Descriptor) string {
	t.Helper()
	addr, err := GetMLDSA87Address(pk, d)
	if err != nil {
		t.Fatalf("setup: GetMLDSA87Address failed: %v", err)
	}
	return fmt.Sprintf("Q%x", addr[:])
}

func TestWalletVerify_RejectsZeroT1Forgery(t *testing.T) {
	d, err := NewMLDSA87Descriptor()
	if err != nil {
		t.Fatalf("setup: NewMLDSA87Descriptor failed: %v", err)
	}
	desc := d.ToDescriptor()
	ctx := walletSigningContext(desc)

	msgs := [][]byte{
		[]byte("wallet forgery message #1"),
		[]byte("wallet forgery message #2"),
	}

	var zeroPK PK // all-zero: rho = 0, t1 = 0
	zeroPKAddr := zeroT1AddrStr(t, zeroPK, d)

	for _, msg := range msgs {
		sig := forgeZeroT1WalletSig(zeroPK[:], ctx, msg)
		if len(sig) != SigSize {
			t.Fatalf("forged sig len %d != %d for zero-t1 key %s", len(sig), SigSize, zeroPKAddr)
		}
		if Verify(msg, sig, &zeroPK, desc) {
			t.Fatalf("SECURITY (finding H1): forged signature verified under the "+
				"all-zero-t1 wallet public key at address %s (msg %q); wallet Verify "+
				"must reject public keys whose t1 region is all zero", zeroPKAddr, msg)
		}
	}
}

// TestWalletVerify_ZeroT1Control guards against a degenerate fix: a real
// wallet key must still accept its genuine signature and reject the
// forgery recipe. Both hold before and after the fix.
func TestWalletVerify_ZeroT1Control(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet failed: %v", err)
	}
	d := w.GetDescriptor()
	desc := d.ToDescriptor()
	ctx := walletSigningContext(desc)
	msg := []byte("wallet control message")

	var zeroPK PK // the forgery key this control contrasts against
	zeroPKAddr := zeroT1AddrStr(t, zeroPK, d)

	genuine, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v (zero-t1 forgery key %s)", err, zeroPKAddr)
	}
	pk := w.GetPK()
	if !Verify(msg, genuine[:], &pk, desc) {
		t.Fatalf("control: a genuine wallet signature must verify under its real key "+
			"(zero-t1 forgery key %s)", zeroPKAddr)
	}

	forged := forgeZeroT1WalletSig(pk[:], ctx, msg)
	if Verify(msg, forged, &pk, desc) {
		t.Fatalf("control: the zero-t1 forgery recipe must NOT verify under a real "+
			"(non-zero-t1) wallet key (zero-t1 forgery key %s)", zeroPKAddr)
	}
}
