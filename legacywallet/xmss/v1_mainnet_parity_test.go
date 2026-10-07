package xmss

import (
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/common"
	xmsscrypto "github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/misc"
)

// These tests pin the descriptor rules the v1 (QRL mainnet) node applied for
// the life of the chain (qrllib <= v1.2.4): byte 2 is ignored on parse and
// written as 0, and the address format is checked only at address derivation.
// qrllib v1.3.1 is stricter on byte 2, but addresses funded under the old
// rules must still migrate, so the old rules are the target here.

// withChecksum recomputes the trailing 4-byte checksum so an address differs
// from a valid one only in the field under test.
func withChecksum(addr [AddressSize]uint8) [AddressSize]uint8 {
	var h [32]uint8
	misc.SHA256(h[:], addr[:DescriptorSize+32])
	copy(addr[DescriptorSize+32:], h[28:])
	return addr
}

// v1ParityFixture returns a signed message, its extended PK and the derived
// address from a fixed-seed height-4 SHAKE_256 wallet, all verified.
func v1ParityFixture(t *testing.T) (msg, sig []uint8, epk [ExtendedPKSize]uint8, addr [AddressSize]uint8) {
	t.Helper()
	var seed [SeedSize]uint8
	for i := range seed {
		seed[i] = uint8(i)
	}
	h, _ := xmsscrypto.ToHeight(4)
	w, err := NewWalletFromSeed(seed, h, xmsscrypto.SHAKE_256, common.SHA256_2X)
	if err != nil {
		t.Fatalf("NewWalletFromSeed: %v", err)
	}
	msg = []byte("v1 parity")
	sig, err = w.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	epk = w.GetPK()
	addr, err = GetXMSSAddressFromPK(epk)
	if err != nil {
		t.Fatalf("GetXMSSAddressFromPK: %v", err)
	}
	if !Verify(msg, sig, epk) || !IsValidXMSSAddress(addr) {
		t.Fatal("control wallet failed to verify / derive a valid address")
	}
	return
}

// v1 verified a PK with a non-zero reserved byte and derived an address from
// it: descriptor normalised to byte 2 = 0, hash over the raw PK.
func TestV1MainnetParity_ReservedByteIgnoredOnParse(t *testing.T) {
	msg, sig, epk, addr := v1ParityFixture(t)
	for _, b := range []byte{0x01, 0x80, 0xFF} {
		bad := epk
		bad[2] = b
		if !Verify(msg, sig, bad) {
			t.Errorf("byte 2 = 0x%02x: Verify = false, want true", b)
		}
		got, err := GetXMSSAddressFromPK(bad)
		if err != nil {
			t.Fatalf("byte 2 = 0x%02x: GetXMSSAddressFromPK: %v", b, err)
		}
		if got[2] != 0 {
			t.Errorf("byte 2 = 0x%02x: address byte 2 = 0x%02x, want 0", b, got[2])
		}
		if got == addr {
			t.Errorf("byte 2 = 0x%02x: address equals the byte-2 = 0 address", b)
		}
		if !IsValidXMSSAddress(got) {
			t.Errorf("byte 2 = 0x%02x: derived address reported invalid", b)
		}
	}
}

// v1 rejected a non-SHA256_2X address format in getAddress/addressIsValid but
// not in verify.
func TestV1MainnetParity_AddrFormatCheckedOnlyAtAddressDerivation(t *testing.T) {
	msg, sig, epk, addr := v1ParityFixture(t)
	bad := epk
	bad[1] = (bad[1] & 0x0F) | (0x01 << 4)
	if !Verify(msg, sig, bad) {
		t.Error("Verify = false, want true")
	}
	if _, err := GetXMSSAddressFromPK(bad); !errors.Is(err, ErrUnsupportedAddressFormat) {
		t.Errorf("GetXMSSAddressFromPK err = %v, want ErrUnsupportedAddressFormat", err)
	}
	badAddr := addr
	badAddr[1] = (badAddr[1] & 0x0F) | (0x01 << 4)
	badAddr = withChecksum(badAddr)
	if IsValidXMSSAddress(badAddr) {
		t.Error("IsValidXMSSAddress = true, want false")
	}
}

// A v1 multisig address (descriptor 0x11 0x00 0x00) is not an XMSS address.
// The literal mainnet descriptor is tested as-is; the height-2 variant shows
// the signature-type nibble alone is enough to reject it.
func TestV1MainnetParity_MultisigDescriptorIsNotXMSS(t *testing.T) {
	for _, desc := range [][]byte{{0x11, 0x00, 0x00}, {0x11, 0x01, 0x00}} {
		if _, err := NewQRLDescriptorFromBytes(desc); err == nil {
			t.Fatalf("descriptor % x parsed as XMSS", desc)
		}
		var addr [AddressSize]uint8
		copy(addr[:], desc)
		addr = withChecksum(addr)
		if IsValidXMSSAddress(addr) {
			t.Fatalf("multisig address % x reported as a valid XMSS address", desc)
		}
	}
}

// GetBytes always writes 0 to the reserved byte.
func TestQRLDescriptor_GetBytesNormalisesReservedByte(t *testing.T) {
	h, _ := xmsscrypto.ToHeight(10)
	if got := NewQRLDescriptor(h, xmsscrypto.SHA2_256, 0, common.SHA256_2X).GetBytes(); got[2] != 0 {
		t.Fatalf("GetBytes()[2] = 0x%02x, want 0", got[2])
	}
}
