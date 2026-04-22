package common

import (
	"bytes"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestSigningContext_CanonicalDescriptor(t *testing.T) {
	desc := descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0, 0}
	ctx := SigningContext(desc)

	expected := []byte{'Z', 'O', 'N', 'D', SigningContextVersion, byte(wallettype.ML_DSA_87), 0, 0}
	if !bytes.Equal(ctx, expected) {
		t.Errorf("ctx = %x, want %x", ctx, expected)
	}
	if len(ctx) != SigningContextSize {
		t.Errorf("len(ctx) = %d, want %d", len(ctx), SigningContextSize)
	}
}

func TestSigningContext_BindsDescriptor(t *testing.T) {
	// Different wallet types must produce different contexts even when
	// metadata bytes are identical.
	ml := SigningContext(descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0, 0})
	sp := SigningContext(descriptor.Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0})
	if bytes.Equal(ml, sp) {
		t.Error("contexts for different wallet types must not collide")
	}

	// Any bit set in the metadata bytes must change the context.
	base := SigningContext(descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0, 0})
	byte1 := SigningContext(descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0x01, 0})
	byte2 := SigningContext(descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0, 0x01})
	if bytes.Equal(base, byte1) || bytes.Equal(base, byte2) || bytes.Equal(byte1, byte2) {
		t.Error("metadata bits must each produce a distinct context")
	}
}

func TestSigningContext_LayoutIsFixedLength(t *testing.T) {
	for _, desc := range []descriptor.Descriptor{
		{byte(wallettype.ML_DSA_87), 0, 0},
		{byte(wallettype.SPHINCSPLUS_256S), 0xFF, 0xFF},
		{byte(wallettype.ML_DSA_87), 0x12, 0x34},
	} {
		ctx := SigningContext(desc)
		if len(ctx) != SigningContextSize {
			t.Errorf("desc %x: len(ctx) = %d, want %d", desc, len(ctx), SigningContextSize)
		}
	}
}

func TestSigningContext_VersionAndPrefix(t *testing.T) {
	desc := descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0, 0}
	ctx := SigningContext(desc)

	if !bytes.Equal(ctx[:len(SigningContextPrefix)], SigningContextPrefix[:]) {
		t.Errorf("prefix mismatch: got %x, want %x", ctx[:len(SigningContextPrefix)], SigningContextPrefix[:])
	}
	if ctx[len(SigningContextPrefix)] != SigningContextVersion {
		t.Errorf("version byte = %d, want %d", ctx[len(SigningContextPrefix)], SigningContextVersion)
	}
	if !bytes.Equal(ctx[len(SigningContextPrefix)+1:], desc[:]) {
		t.Errorf("descriptor suffix mismatch: got %x, want %x", ctx[len(SigningContextPrefix)+1:], desc[:])
	}
}
