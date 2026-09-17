// Regression tests for the all-zero-t1 ML-DSA-87 public key.
//
// A public key whose t1 region (bytes SEED_BYTES..PKSize) is all zero is
// universally forgeable: with t1 = 0 the verifier's reconstructed commitment
// no longer depends on the challenge, so (z = 0, h = 0,
// c~ = SHAKE256(mu || w1Encode(0))) is a valid signature for any message,
// computable from public data alone.
//
// The FIPS 204 primitive (crypto/ml_dsa_87.Verify) deliberately accepts such
// signatures — that is what Algorithm 8 specifies and what the
// C2SP/wycheproof ZeroPublicKey vectors require. The rejection is a
// key-validation policy and lives in this package: BytesToPK / HexStrToPK
// refuse to construct the key, and Verify refuses to use it. Verify must
// check independently because PK is a plain array type and can be
// constructed without BytesToPK.

package ml_dsa_87

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	mldsa "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
)

// forgeZeroT1WalletSig builds the raw forged signature bytes for a t1 = 0
// public key and the given signing context, using only public inputs.
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

	w1enc := make([]byte, mldsa.K*mldsa.POLY_W1_PACKED_BYTES) // w1Encode(0)
	cTilde := make([]byte, mldsa.C_TILDE_BYTES)
	st.Reset()
	_, _ = st.Write(mu)
	_, _ = st.Write(w1enc)
	_, _ = st.Read(cTilde)

	// sig = c~ || polyZPack(0) * L || h = 0 (OMEGA+K zero bytes).
	// polyZPack of an all-zero polynomial is the repeating 5-byte group
	// {0x00,0x00,0x08,0x00,0x80} (t = GAMMA1 - 0 = 2^19, two per five bytes).
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

// zeroT1PK returns a PK with the given rho byte repeated and t1 = 0,
// constructed directly (bypassing BytesToPK) to exercise the Verify guard.
func zeroT1PK(rho byte) PK {
	var pk PK
	for i := 0; i < mldsa.SEED_BYTES; i++ {
		pk[i] = rho
	}
	return pk
}

// TestWalletVerify_RejectsZeroT1Forgery is the security assertion at the
// wallet layer. The PK is built directly, not via BytesToPK, so this proves
// Verify is a chokepoint in its own right.
func TestWalletVerify_RejectsZeroT1Forgery(t *testing.T) {
	d, err := NewMLDSA87Descriptor()
	if err != nil {
		t.Fatalf("setup: NewMLDSA87Descriptor: %v", err)
	}
	desc := d.ToDescriptor()
	ctx := common.SigningContext(desc)

	cases := []struct {
		name string
		rho  byte
		msg  []byte
	}{
		{"all-zero pk", 0x00, []byte("wallet forgery message #1")},
		{"all-zero pk, second message", 0x00, []byte("wallet forgery message #2")},
		{"non-zero rho, zero t1", 0xab, []byte("rho does not save you")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk := zeroT1PK(tc.rho)
			sig := forgeZeroT1WalletSig(pk[:], ctx, tc.msg)
			if len(sig) != SigSize {
				t.Fatalf("forged sig len %d != %d", len(sig), SigSize)
			}
			// The crypto layer refuses to even construct this key; that is the
			// mechanism wallet Verify relies on. (That the forgery verifies
			// under the raw FIPS 204 primitive is pinned in-package by
			// crypto/ml_dsa_87's TestVerify_AcceptsZeroT1ForgeryByDesign.)
			if _, err := mldsa.ParsePublicKey(pk[:]); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
				t.Fatalf("setup: ParsePublicKey err = %v, want ErrWeakPublicKey", err)
			}
			if Verify(tc.msg, sig, &pk, desc) {
				t.Fatal("SECURITY: forged signature verified under an all-zero-t1 " +
					"wallet public key; wallet Verify must reject keys whose t1 is all zero")
			}
		})
	}
}

// TestWalletVerify_ZeroT1Control guards against a degenerate fix: a real key
// must still accept its genuine signature and reject the forgery recipe.
func TestWalletVerify_ZeroT1Control(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet: %v", err)
	}
	desc := w.GetDescriptor().ToDescriptor()
	ctx := common.SigningContext(desc)
	msg := []byte("wallet control message")

	genuine, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign: %v", err)
	}
	pk := w.GetPK()
	if !Verify(msg, genuine[:], &pk, desc) {
		t.Fatal("control: genuine signature must verify under its real key")
	}
	if Verify(msg, forgeZeroT1WalletSig(pk[:], ctx, msg), &pk, desc) {
		t.Fatal("control: the zero-t1 forgery recipe must NOT verify under a real key")
	}
}

// TestBytesToPK_RejectsZeroT1 covers fail-fast rejection on import, for
// both the all-zero key and a key with non-zero rho but zero t1.
func TestBytesToPK_RejectsZeroT1(t *testing.T) {
	for _, rho := range []byte{0x00, 0xab} {
		pk := zeroT1PK(rho)
		_, err := BytesToPK(pk[:])
		if err == nil {
			t.Fatalf("rho=%#x: BytesToPK accepted a zero-t1 public key", rho)
		}
		if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Fatalf("rho=%#x: err = %v, want errors.Is(..., ErrWeakPublicKey)", rho, err)
		}
		_, err = HexStrToPK(hex.EncodeToString(pk[:]))
		if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Fatalf("rho=%#x: HexStrToPK err = %v, want ErrWeakPublicKey", rho, err)
		}
	}
}

// TestBytesToPK_AcceptsRealKey is the control for the import guard.
func TestBytesToPK_AcceptsRealKey(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet: %v", err)
	}
	pk := w.GetPK()
	got, err := BytesToPK(pk[:])
	if err != nil {
		t.Fatalf("BytesToPK rejected a real key: %v", err)
	}
	if got != pk {
		t.Fatal("BytesToPK round-trip mismatch")
	}
}
