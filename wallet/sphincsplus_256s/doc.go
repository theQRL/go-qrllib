// Package sphincsplus_256s provides a wallet implementation for SPHINCS+-256s
// signatures on QRL V2.0.
//
// # Status: forward placeholder, not currently active
//
// SPHINCSPLUS_256S is reserved in the QRL descriptor format as a forward
// placeholder for QRL's eventual adoption of the stateless hash-based
// signature family — now standardised by NIST as SLH-DSA in FIPS 205. QRL
// is awaiting the finalisation of the specific NIST-approved parameter set
// it intends to adopt before enabling the wallet type for issuance.
//
// Until that activation:
//
//   - All public wallet constructors (NewWallet, NewWalletFromSeed, etc.)
//     return [github.com/theQRL/go-qrllib/wallet/common.ErrWalletTypeNotIssuable].
//   - [Verify] returns false regardless of signature material.
//   - Descriptors with type SPHINCSPLUS_256S still parse via
//     [github.com/theQRL/go-qrllib/wallet/common/descriptor.Descriptor.IsValid]
//     so the on-wire layout does not need to change at activation time.
//
// The implementation below is otherwise complete and is exercised end-to-end
// by the package test suite via an internal opt-in, so SLH-DSA activation
// is a one-line change to the IsIssuable / IsVerifiable switches in the
// wallettype package. See
// [github.com/theQRL/go-qrllib/wallet/common/wallettype.WalletType.IsIssuable].
//
// This package wraps the low-level [github.com/theQRL/go-qrllib/crypto/sphincsplus_256s]
// package and provides:
//
//   - QRL address generation with proper descriptor formatting
//   - Domain-separated message prefix bound to the wallet descriptor
//   - Seed management and mnemonic conversion
//   - Signature verification with address descriptor validation
//
// # Signature Binding
//
// SPHINCS+-256s has no native signing-context parameter. To bind every
// signature to its originating descriptor, this wallet package prepends the
// [github.com/theQRL/go-qrllib/wallet/common.SigningContext] bytes to the
// message before passing it to the underlying primitive:
//
//	prefix = "ZOND" || SigningContextVersion || descriptor   (fixed 8 bytes)
//	signed = prefix || message
//
// Because the prefix is fixed-length, the concatenation is canonical: an
// attacker cannot shift the prefix boundary to produce an alternative valid
// (descriptor, message) pair. [Verify] reconstructs the same prefix from the
// descriptor it is given, so a signature produced under descriptor D1 fails
// verification under any other descriptor D2. Bumping SigningContextVersion is
// a signature-format break and must coincide with a coordinated consensus
// activation.
//
// # Seed Derivation
//
// The wallet uses a 48-byte common seed that is expanded with SHAKE-256 to
// produce the 96-byte seed for SPHINCS+ key generation:
//
//	Common Seed (48 bytes) → SHAKE-256 → SPHINCS+ Seed (96 bytes) → Keypair
//
// This differs from ML-DSA-87 which uses SHA-256 for seed derivation.
//
// # Address Format
//
// QRL addresses are generated from the public key with a descriptor prefix using SHAKE256:
//
//	Address = "Q" + hex(SHAKE256(Descriptor || PK)[:64])
//
// This produces a standard 64-byte address (plus 'Q' prefix).
//
// # Signature Size
//
// SPHINCS+-256s has large signatures (29,792 bytes) compared to lattice-based
// schemes. This is the trade-off for hash-based security assumptions.
//
// # Example Usage
//
//	// Create a fresh wallet, or restore from a mnemonic / extended seed.
//	w, err := sphincsplus_256s.NewWallet()
//	// w, err := sphincsplus_256s.NewWalletFromMnemonic(phrase)
//	// w, err := sphincsplus_256s.NewWalletFromHexExtendedSeed(hexSeed)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer w.Zeroize()
//
//	address := w.GetAddressStr()              // "Q" + hex(64 bytes)
//	pk      := w.GetPK()
//	desc    := w.GetDescriptor().ToDescriptor()
//
//	sig, err := w.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ok := sphincsplus_256s.Verify(message, sig[:], &pk, desc)
//
// # Thread Safety
//
// A Wallet instance has the same thread safety characteristics as the underlying
// SphincsPlus256s type: safe for concurrent reads, but Sign should not be called
// concurrently on the same instance.
package sphincsplus_256s
