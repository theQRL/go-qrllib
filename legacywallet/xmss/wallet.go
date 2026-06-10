package xmss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	misc2 "github.com/theQRL/go-qrllib/wallet/misc"

	"github.com/theQRL/go-qrllib/common"
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/legacywallet"
)

type XMSSWallet struct {
	seed [SeedSize]uint8
	desc *QRLDescriptor
	xmss *xmss.XMSS
}

// NewWalletFromSeed constructs a legacy XMSS wallet from a raw seed,
// height, hash function, and address format. Used both for fresh wallet
// creation and for re-deriving an existing v1 address from its seed.
//
// hashFunction must be one of [xmss.SHA2_256], [xmss.SHAKE_128], or
// [xmss.SHAKE_256]. SHAKE_128 is retained for QRL v1 legacy address
// compatibility from the pre-standardisation XMSS implementation and is
// not recommended for new wallets — see the package documentation and
// [xmss.SHAKE_128] for the rationale. Existing SHAKE_128 addresses
// remain fully recoverable and signable through this constructor.
func NewWalletFromSeed(seed [SeedSize]uint8, height xmss.Height, hashFunction xmss.HashFunction, addrFormatType common.AddrFormatType) (*XMSSWallet, error) {
	// Defense-in-depth (TOB-QRLLIB-13): refuse an invalid HashFunction
	// before constructing the descriptor. crypto/xmss.InitializeTree
	// also gates this, but rejecting at the wallet boundary surfaces a
	// wallet-typed error to the caller and avoids constructing a
	// QRLDescriptor that would never produce a usable key.
	if !hashFunction.IsValid() {
		return nil, fmt.Errorf("invalid hash function: %w", cryptoerrors.ErrInvalidHashFunction)
	}

	signatureType := legacywallet.WalletTypeXMSS // Signature Type hard coded for now
	if height > xmss.MaxHeight {
		return nil, fmt.Errorf("height %d exceeds maximum %d", height, xmss.MaxHeight)
	}
	desc := NewQRLDescriptor(height, hashFunction, signatureType, addrFormatType)

	tree, err := xmss.InitializeTree(desc.height, desc.hashFunction, seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XMSS tree: %w", err)
	}

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: tree,
	}, nil
}

func NewWalletFromExtendedSeed(extendedSeed [ExtendedSeedSize]uint8) (*XMSSWallet, error) {
	desc, err := NewQRLDescriptorFromExtendedSeed(extendedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse descriptor: %w", err)
	}

	var seed [SeedSize]uint8
	copy(seed[:], extendedSeed[DescriptorSize:])

	tree, err := xmss.InitializeTree(desc.height, desc.hashFunction, seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XMSS tree: %w", err)
	}

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: tree,
	}, nil
}

// NewWalletFromHeight generates a fresh XMSS wallet of the given height
// using the supplied hashFunction and a system-random 48-byte seed.
//
// Same SHAKE_128 caveat as NewWalletFromSeed: SHAKE_128 is a QRL-specific
// extension retained for legacy compatibility and is not recommended for
// new wallets. Prefer SHAKE_256 (or SHA2_256) for any newly-created
// XMSS wallet, and prefer ML-DSA-87 (FIPS 204) over XMSS for any new
// signing identity that does not need to inherit a v1 address.
func NewWalletFromHeight(height xmss.Height, hashFunction xmss.HashFunction) (*XMSSWallet, error) {
	var seed [SeedSize]uint8
	_, err := rand.Read(seed[:])
	if err != nil {
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return NewWalletFromSeed(seed, height, hashFunction, common.SHA256_2X)
}

func (w *XMSSWallet) SetIndex(newIndex uint32) error {
	return w.xmss.SetIndex(newIndex)
}

func (w *XMSSWallet) GetHeight() xmss.Height {
	return w.xmss.GetHeight()
}

func (w *XMSSWallet) GetSeed() [SeedSize]uint8 {
	return w.seed
}

func (w *XMSSWallet) GetExtendedSeed() [ExtendedSeedSize]uint8 {
	var extendedSeed [ExtendedSeedSize]uint8
	descBytes := w.desc.GetBytes()
	seed := w.GetSeed()
	copy(extendedSeed[:3], descBytes[:])
	copy(extendedSeed[3:], seed[:])
	return extendedSeed
}

func (w *XMSSWallet) GetHexSeed() string {
	eSeed := w.GetExtendedSeed()
	return "0x" + hex.EncodeToString(eSeed[:])
}

func (w *XMSSWallet) GetMnemonic() (string, error) {
	extendedSeed := w.GetExtendedSeed()
	return misc2.BinToMnemonic(extendedSeed[:])
}

func (w *XMSSWallet) GetRoot() []uint8 {
	return w.xmss.GetRoot()
}

func (w *XMSSWallet) GetPK() [ExtendedPKSize]uint8 {
	//    PK format
	//     3 QRL_DESCRIPTOR
	//    32 root address
	//    32 pub_seed

	desc := w.desc.GetBytes()
	root := w.GetRoot()
	pubSeed := w.xmss.GetPKSeed()

	var output [ExtendedPKSize]uint8
	offset := 0
	copy(output[:], desc[:])
	offset += len(desc)
	copy(output[offset:], root[:])
	offset += len(root)
	copy(output[offset:], pubSeed[:])
	return output
}

func (w *XMSSWallet) GetSK() []uint8 {
	return w.xmss.GetSK()
}

func (w *XMSSWallet) GetAddress() ([AddressSize]uint8, error) {
	return GetXMSSAddressFromPK(w.GetPK())
}

func (w *XMSSWallet) GetIndex() uint32 {
	return w.xmss.GetIndex()
}

// Sign produces an XMSS signature over message and advances the
// wallet's internal one-time-signature (OTS) index by one.
//
// # CRITICAL WARNING — STATEFUL SIGNATURE SCHEME
//
// XMSS is a STATEFUL signature scheme. Each signature consumes a unique
// OTS index. Reusing an index — even for a different message — exposes
// enough of the secret key to allow an attacker to forge signatures for
// ANY message.
//
// Callers MUST:
//
//  1. Persist the UPDATED index — obtained via [XMSSWallet.GetIndex] —
//     to durable storage AFTER this call returns and BEFORE the returned
//     signature is used or broadcast. If the persistence step fails, the
//     signature MUST NOT be used.
//  2. Never call Sign concurrently on the same XMSSWallet instance. The
//     index is not protected by locks, and concurrent signing will
//     corrupt the BDS state and may lead to index reuse.
//  3. Never restore an XMSSWallet from a backup whose persisted index is
//     behind the true last-used index — doing so would re-use indices.
//  4. Plan for key rotation before index exhaustion (2^height signatures).
//
// See the package documentation and [github.com/theQRL/go-qrllib/crypto/xmss]
// for the full safe-usage pattern, including the recovery procedure that
// uses [XMSSWallet.SetIndex] to fast-forward the BDS state when restoring
// from a persisted index.
func (w *XMSSWallet) Sign(message []uint8) ([]uint8, error) {
	return w.xmss.Sign(message)
}

// Zeroize clears sensitive key material from memory: the wallet's
// retained 48-byte seed and the underlying XMSS tree's secret key, seed
// copy, and BDS traversal state. Call this when the wallet is no longer
// needed — the same contract as the Zeroize methods on the v2 wallet
// types. Best-effort under Go's memory model; see SECURITY.md
// "Key Zeroization".
func (w *XMSSWallet) Zeroize() {
	for i := range w.seed {
		w.seed[i] = 0
	}
	if w.xmss != nil {
		w.xmss.Zeroize()
	}
}

func Verify(message, signature []uint8, extendedPK [ExtendedPKSize]uint8) (result bool) {
	height, err := xmss.GetHeightFromSigSize(uint32(len(signature)), xmss.WOTSParamW)
	if err != nil {
		return false
	}

	desc, err := NewQRLDescriptorFromExtendedPK(&extendedPK)
	if err != nil {
		return false
	}

	if desc.GetSignatureType() != legacywallet.WalletTypeXMSS {
		//coverage:ignore
		//rationale: NewQRLDescriptorFromExtendedPK validates signature type, only XMSS (0) is accepted
		return false
	}

	if desc.GetHeight() != height {
		return false
	}

	pk := extendedPK[DescriptorSize:]

	return xmss.Verify(desc.hashFunction, message, signature, pk)
}
