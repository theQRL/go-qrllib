package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/misc"
)

type Wallet struct {
	desc Descriptor
	d    *ml_dsa_87.MLDSA87
	seed common.Seed
}

func NewWallet() (*Wallet, error) {
	var seed common.Seed
	_, err := rand.Read(seed[:])
	if err != nil {
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.ML_DSA_87, err)
	}
	return NewWalletFromSeed(seed)
}

func NewWalletFromSeed(seed common.Seed) (*Wallet, error) {
	desc, err := NewMLDSA87Descriptor()
	if err != nil {
		//coverage:ignore
		//rationale: descriptor uses hardcoded valid wallet type, cannot fail
		return nil, fmt.Errorf("failed to create descriptor: %w", err)
	}
	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil {
		//coverage:ignore
		//rationale: keypair generation only fails if buffer sizes wrong, Go's type system guarantees correct sizes
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexSeed(hexSeed string) (*Wallet, error) {
	if strings.HasPrefix(hexSeed, "0x") || strings.HasPrefix(hexSeed, "0X") {
		hexSeed = hexSeed[2:]
	}
	binSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	if len(binSeed) != common.SeedSize {
		return nil, fmt.Errorf(common.ErrInvalidSeedLength, wallettype.ML_DSA_87, len(binSeed), common.SeedSize)
	}
	var seed common.Seed
	copy(seed[:], binSeed[:])
	return NewWalletFromSeed(seed)
}

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	desc, err := NewMLDSA87DescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrDescriptorFromExtendedSeed, wallettype.ML_DSA_87, err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		//coverage:ignore
		//rationale: ExtendedSeed.GetSeedBytes() always returns exactly SeedSize bytes
		return nil, fmt.Errorf(common.ErrExtendedSeedToSeed, wallettype.ML_DSA_87, err)
	}

	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil {
		//coverage:ignore
		//rationale: keypair generation only fails if buffer sizes wrong, Go's type system guarantees correct sizes
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexExtendedSeed(hexExtendedSeed string) (*Wallet, error) {
	if strings.HasPrefix(hexExtendedSeed, "0x") || strings.HasPrefix(hexExtendedSeed, "0X") {
		hexExtendedSeed = hexExtendedSeed[2:]
	}
	binExtendedSeed, err := hex.DecodeString(hexExtendedSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	if len(binExtendedSeed) != common.ExtendedSeedSize {
		return nil, fmt.Errorf(common.ErrInvalidExtendedSeedLength, wallettype.ML_DSA_87, len(binExtendedSeed), common.ExtendedSeedSize)
	}
	var extendedSeed common.ExtendedSeed
	copy(extendedSeed[:], binExtendedSeed[:])
	return NewWalletFromExtendedSeed(extendedSeed)
}

func NewWalletFromMnemonic(mnemonic string) (*Wallet, error) {
	bin, err := misc.MnemonicToBin(mnemonic)
	if err != nil {
		return nil, fmt.Errorf(common.ErrMnemonicToBin, wallettype.ML_DSA_87, err)
	}

	extendedSeed, err := common.NewExtendedSeedFromBytes(bin)
	if err != nil {
		return nil, fmt.Errorf(common.ErrExtendedSeedFromMnemonic, wallettype.ML_DSA_87, err)
	}

	return NewWalletFromExtendedSeed(extendedSeed)
}

func (w *Wallet) GetSeed() common.Seed {
	return w.seed
}

func (w *Wallet) GetExtendedSeed() (common.ExtendedSeed, error) {
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		return common.ExtendedSeed{}, fmt.Errorf(common.ErrExtendedSeedFromDescriptorAndSeed, wallettype.ML_DSA_87, err)
	}
	return extendedSeed, nil
}

func (w *Wallet) GetHexSeed() (string, error) {
	eSeed, err := w.GetExtendedSeed()
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(eSeed[:]), nil
}

func (w *Wallet) GetMnemonic() (string, error) {
	eSeed, err := w.GetExtendedSeed()
	if err != nil {
		return "", err
	}
	mnemonic, err := misc.BinToMnemonic(eSeed[:])
	if err != nil {
		//coverage:ignore
		//rationale: returned ExtendedSeed is always 51 bytes (divisible by 3) and buffer writes never error
		return "", err
	}
	return mnemonic, nil
}

func (w *Wallet) GetPK() PK {
	return w.d.GetPK()
}

func (w *Wallet) GetSK() [SKSize]uint8 {
	return w.d.GetSK()
}

func (w *Wallet) GetDescriptor() Descriptor {
	return w.desc
}

func (w *Wallet) GetAddress() [common.AddressSize]uint8 {
	pk := w.GetPK()
	return common.UnsafeGetAddress(pk[:], w.desc.ToDescriptor())
}

func (w *Wallet) GetAddressStr() string {
	addr := w.GetAddress()
	return fmt.Sprintf("Q%x", addr[:])
}

// GetChecksumAddressStr returns the EIP-55-style mixed-case checksummed
// string form of the wallet address (see common.ToChecksumAddress). Use this
// in user-facing displays where transcription-error detection is desirable;
// GetAddressStr remains the canonical lowercase form for backward
// compatibility with code that string-compares addresses.
func (w *Wallet) GetChecksumAddressStr() string {
	return common.ToChecksumAddress(w.GetAddress())
}

// Sign produces an ML-DSA-87 signature over message using the
// descriptor-bound signing context. Signing is hedged by default as per
// FIPS 204: each call mixes fresh `crypto/rand` randomness into the per-signature
// `RND_BYTES`, so two calls over the same message produce distinct signatures,
// both of which verify under the same public key + descriptor. See the
// [github.com/theQRL/go-qrllib/crypto/ml_dsa_87] package doc
// "Signing Mode" section for the full discussion.
func (w *Wallet) Sign(message []uint8) ([SigSize]uint8, error) {
	return w.d.Sign(common.SigningContext(w.desc.ToDescriptor()), message)
}

// Zeroize clears sensitive key material from memory.
// This should be called when the Wallet is no longer needed.
func (w *Wallet) Zeroize() {
	for i := range w.seed {
		w.seed[i] = 0
	}
	w.d.Zeroize()
}

// Verify reports whether the signature is a valid ML-DSA-87 signature
// over message under pk and the descriptor-bound signing context.
// Returns false (rather than panicking) if pk is nil. (TOB-QRLLIB-11)
func Verify(message, signature []uint8, pk *PK, desc [descriptor.DescriptorSize]byte) (result bool) {
	if pk == nil {
		return false
	}
	d, err := NewMLDSA87DescriptorFromDescriptorBytes(desc)
	if err != nil {
		return false
	}

	if len(signature) != SigSize {
		// Invalid signature size - return false instead of panicking
		return false
	}

	var sig [SigSize]uint8
	copy(sig[:], signature)

	pk2 := (*[ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8)(pk)

	return ml_dsa_87.Verify(common.SigningContext(d.ToDescriptor()), message, sig, pk2)
}
